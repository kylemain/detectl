import json
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from detectl.cli import main
from detectl.exceptions import NotFoundError
from detectl.models import Alert, ListObject, QueryResult, Rule


class FakeAdapter:
    name = "fake"

    def __init__(self):
        self.create_rule_called = False
        self.update_rule_called = False

    def test_connection(self):
        return True

    def list_rules(self, **filters):
        return [Rule(id="r1", name="Rule 1", query="q")]

    def get_rule(self, rule_id):
        if rule_id != "r1":
            raise NotFoundError(f"no such rule: {rule_id}")
        return Rule(id="r1", name="Rule 1", query="q", severity="medium")

    def create_rule(self, rule):
        self.create_rule_called = True
        return Rule(id="new", name=rule.name, query=rule.query)

    def update_rule(self, rule_id, rule):
        self.update_rule_called = True
        return Rule(id=rule_id, name=rule.name, query=rule.query)

    def list_lists(self, kind=None):
        return [ListObject(id="l1", name="List 1", kind="watchlist", items=["a"])]

    def list_alerts(self, **filters):
        return [Alert(id="a1", title="Alert 1", severity="high", status="open")]

    def run_query(self, query, **kwargs):
        return QueryResult(columns=["host"], rows=[{"host": "x"}])


class TestCli(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_targets(self):
        result = self.runner.invoke(main, ["targets"])
        self.assertEqual(result.exit_code, 0)
        for name in ("splunk", "elastic", "sentinel", "crowdstrike"):
            self.assertIn(name, result.output)

    def test_targets_plain_list_when_not_a_tty(self):
        # CliRunner's captured output isn't a real tty, so this is really
        # just documenting/pinning the default (piped) behavior explicitly.
        result = self.runner.invoke(main, ["targets"])
        self.assertEqual(result.exit_code, 0)
        lines = result.output.strip().splitlines()
        self.assertEqual(sorted(lines), sorted(["splunk", "elastic", "sentinel", "crowdstrike", "qradar", "sumologic", "chronicle"]))

    @patch("detectl.cli._stdout_is_tty", return_value=True)
    def test_targets_renders_rich_table_when_tty(self, _mock_tty):
        result = self.runner.invoke(main, ["targets"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("detectl supported platforms", result.output)
        for name in ("splunk", "elastic", "sentinel", "crowdstrike", "qradar", "sumologic", "chronicle"):
            self.assertIn(name, result.output)
        self.assertIn("Ad-hoc query language", result.output)
        self.assertIn("Rules resource", result.output)

    def test_platform_required(self):
        result = self.runner.invoke(main, ["rules", "list"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("--platform", result.output)

    @patch("detectl.cli.get_adapter", return_value=FakeAdapter())
    def test_test_connection(self, _mock):
        result = self.runner.invoke(main, ["-p", "splunk", "test-connection"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("OK", result.output)

    @patch("detectl.cli.get_adapter", return_value=FakeAdapter())
    def test_rules_list(self, _mock):
        result = self.runner.invoke(main, ["-p", "splunk", "rules", "list"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data[0]["name"], "Rule 1")

    @patch("detectl.cli.get_adapter", return_value=FakeAdapter())
    def test_rules_get_not_found_reports_error(self, _mock):
        result = self.runner.invoke(main, ["-p", "splunk", "rules", "get", "missing"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("error", result.output)

    @patch("detectl.cli.get_adapter", return_value=FakeAdapter())
    def test_lists_list(self, _mock):
        result = self.runner.invoke(main, ["-p", "splunk", "lists", "list"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data[0]["kind"], "watchlist")

    @patch("detectl.cli.get_adapter", return_value=FakeAdapter())
    def test_alerts_list(self, _mock):
        result = self.runner.invoke(main, ["-p", "splunk", "alerts", "list"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data[0]["severity"], "high")

    @patch("detectl.cli.get_adapter", return_value=FakeAdapter())
    def test_query(self, _mock):
        result = self.runner.invoke(main, ["-p", "splunk", "query", "index=main"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data["rows"], [{"host": "x"}])

    @patch("detectl.cli.get_adapter")
    def test_rules_create_dry_run_does_not_call_adapter(self, mock_get_adapter):
        adapter = FakeAdapter()
        mock_get_adapter.return_value = adapter
        with self.runner.isolated_filesystem():
            with open("rule.json", "w") as fh:
                json.dump({"name": "New Rule", "query": "q"}, fh)
            result = self.runner.invoke(main, ["-p", "splunk", "rules", "create", "-f", "rule.json", "--dry-run"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("PLAN: create", result.output)
        self.assertIn("New Rule", result.output)
        self.assertFalse(adapter.create_rule_called)

    @patch("detectl.cli.get_adapter")
    def test_rules_update_dry_run_shows_diff_and_does_not_apply(self, mock_get_adapter):
        adapter = FakeAdapter()
        mock_get_adapter.return_value = adapter
        with self.runner.isolated_filesystem():
            with open("rule.json", "w") as fh:
                json.dump({"name": "Rule 1", "query": "q", "severity": "critical"}, fh)
            result = self.runner.invoke(main, ["-p", "splunk", "rules", "update", "r1", "-f", "rule.json", "--dry-run"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("PLAN: update", result.output)
        self.assertIn("'medium'", result.output)  # old value shown
        self.assertIn("'critical'", result.output)  # new value shown
        self.assertFalse(adapter.update_rule_called)

    @patch("detectl.cli.get_adapter")
    def test_rules_create_from_sigma(self, mock_get_adapter):
        adapter = FakeAdapter()
        mock_get_adapter.return_value = adapter
        sigma_yaml = """
        title: Test Sigma Rule
        level: high
        logsource: {category: process_creation, product: windows}
        detection:
          selection: {CommandLine|contains: 'evil'}
          condition: selection
        """
        with self.runner.isolated_filesystem():
            with open("rule.yml", "w") as fh:
                fh.write(sigma_yaml)
            result = self.runner.invoke(main, ["-p", "elastic", "rules", "create-from-sigma", "rule.yml"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(adapter.create_rule_called)
        data = json.loads(result.output)
        self.assertEqual(data["name"], "Test Sigma Rule")
        self.assertIn("evil", data["query"])

    @patch("detectl.cli.get_adapter")
    def test_rules_create_from_sigma_dry_run(self, mock_get_adapter):
        adapter = FakeAdapter()
        mock_get_adapter.return_value = adapter
        sigma_yaml = """
        title: Test Sigma Rule
        logsource: {product: windows}
        detection:
          selection: {CommandLine|contains: 'evil'}
          condition: selection
        """
        with self.runner.isolated_filesystem():
            with open("rule.yml", "w") as fh:
                fh.write(sigma_yaml)
            result = self.runner.invoke(
                main, ["-p", "qradar", "rules", "create-from-sigma", "rule.yml", "--dry-run"]
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("PLAN: create (via sigmux)", result.output)
        self.assertIn("_sigmux_target", result.output)
        self.assertFalse(adapter.create_rule_called)

    @patch("detectl.cli.get_adapter")
    def test_rules_create_from_sigma_unknown_target_reported(self, mock_get_adapter):
        # every current platform maps to a real sigmux target 1:1, so this
        # exercises the guard rather than a real gap -- temporarily point
        # an existing platform's mapping at a bogus target name.
        from detectl import cli as cli_module

        original = cli_module._SIGMUX_TARGET_FOR["splunk"]
        cli_module._SIGMUX_TARGET_FOR["splunk"] = "not-a-real-sigmux-target"
        try:
            adapter = FakeAdapter()
            mock_get_adapter.return_value = adapter
            with self.runner.isolated_filesystem():
                with open("rule.yml", "w") as fh:
                    fh.write("title: t\nlogsource: {product: windows}\ndetection:\n  s: {F: v}\n  condition: s\n")
                result = self.runner.invoke(main, ["-p", "splunk", "rules", "create-from-sigma", "rule.yml"])
        finally:
            cli_module._SIGMUX_TARGET_FOR["splunk"] = original
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("no 'not-a-real-sigmux-target' target", result.output)


if __name__ == "__main__":
    unittest.main()
