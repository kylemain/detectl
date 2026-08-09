import json
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from detectl.cli import main
from detectl.exceptions import NotFoundError
from detectl.models import Alert, ListObject, QueryResult, Rule


class FakeAdapter:
    name = "fake"

    def test_connection(self):
        return True

    def list_rules(self, **filters):
        return [Rule(id="r1", name="Rule 1", query="q")]

    def get_rule(self, rule_id):
        if rule_id != "r1":
            raise NotFoundError(f"no such rule: {rule_id}")
        return Rule(id="r1", name="Rule 1", query="q")

    def create_rule(self, rule):
        return Rule(id="new", name=rule.name, query=rule.query)

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


if __name__ == "__main__":
    unittest.main()
