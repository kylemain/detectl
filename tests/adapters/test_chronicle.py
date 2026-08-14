import unittest

from detectl.adapters.chronicle import ChronicleAdapter
from detectl.exceptions import UnsupportedOperationError
from detectl.models import ListObject, Rule
from tests.helpers import FakeResponse, FakeSession, route_handler

BASE = "https://us-chronicle.googleapis.com/v1beta"
INSTANCE_PATH = "/projects/proj1/locations/us/instances/inst1"


def make_adapter(routes):
    session = FakeSession(route_handler(BASE, routes))
    adapter = ChronicleAdapter(
        project="proj1", location="us", instance="inst1", access_token="tok", session=session
    )
    return adapter, session


class TestChronicleAdapter(unittest.TestCase):
    def test_connection_sends_bearer_header(self):
        adapter, session = make_adapter({("GET", INSTANCE_PATH + "/rules"): FakeResponse(200, {"rules": []})})
        self.assertTrue(adapter.test_connection())
        self.assertEqual(session.headers["Authorization"], "Bearer tok")

    def test_list_rules(self):
        entry = {"name": f"projects/proj1/locations/us/instances/inst1/rules/r1", "text": "rule r1 { ... }"}
        adapter, _ = make_adapter({("GET", INSTANCE_PATH + "/rules"): FakeResponse(200, {"rules": [entry]})})
        rules = adapter.list_rules()
        self.assertEqual(rules[0].id, "r1")
        self.assertEqual(rules[0].query, "rule r1 { ... }")

    def test_get_rule_merges_deployment_enabled_state(self):
        entry = {"name": "projects/proj1/locations/us/instances/inst1/rules/r1", "text": "rule r1 { ... }"}
        adapter, _ = make_adapter(
            {
                ("GET", INSTANCE_PATH + "/rules/r1"): FakeResponse(200, entry),
                ("GET", INSTANCE_PATH + "/rules/r1/deployment"): FakeResponse(200, {"enabled": False}),
            }
        )
        rule = adapter.get_rule("r1")
        self.assertFalse(rule.enabled)

    def test_create_rule_syncs_deployment(self):
        created = {"name": "projects/proj1/locations/us/instances/inst1/rules/r2", "text": "rule r2 { ... }"}
        adapter, session = make_adapter(
            {
                ("POST", INSTANCE_PATH + "/rules"): FakeResponse(200, created),
                ("PATCH", INSTANCE_PATH + "/rules/r2/deployment"): FakeResponse(200, {}),
                ("GET", INSTANCE_PATH + "/rules/r2"): FakeResponse(200, created),
                ("GET", INSTANCE_PATH + "/rules/r2/deployment"): FakeResponse(200, {"enabled": True}),
            }
        )
        rule = adapter.create_rule(Rule(id=None, name="r2", query="rule r2 { ... }"))
        self.assertEqual(rule.id, "r2")
        self.assertTrue(rule.enabled)
        patch_call = [c for c in session.calls if c[0] == "PATCH"][0]
        self.assertEqual(patch_call[2]["json"], {"enabled": True})

    def test_delete_rule(self):
        adapter, session = make_adapter({("DELETE", INSTANCE_PATH + "/rules/r1"): FakeResponse(200, {})})
        adapter.delete_rule("r1")
        self.assertEqual(session.calls[-1][0], "DELETE")

    def test_set_rule_enabled(self):
        entry = {"name": "projects/proj1/locations/us/instances/inst1/rules/r1", "text": "t"}
        adapter, session = make_adapter(
            {
                ("PATCH", INSTANCE_PATH + "/rules/r1/deployment"): FakeResponse(200, {}),
                ("GET", INSTANCE_PATH + "/rules/r1"): FakeResponse(200, entry),
                ("GET", INSTANCE_PATH + "/rules/r1/deployment"): FakeResponse(200, {"enabled": False}),
            }
        )
        rule = adapter.disable_rule("r1")
        self.assertFalse(rule.enabled)

    def test_list_lists_kind_from_description_tag(self):
        entry = {
            "name": "projects/proj1/locations/us/instances/inst1/referenceLists/baddies",
            "description": "IR list detectl_kind:blocklist",
            "entries": [{"value": "1.2.3.4"}],
        }
        adapter, _ = make_adapter(
            {("GET", INSTANCE_PATH + "/referenceLists"): FakeResponse(200, {"referenceLists": [entry]})}
        )
        lists = adapter.list_lists()
        self.assertEqual(lists[0].kind, "blocklist")
        self.assertEqual(lists[0].items, ["1.2.3.4"])

    def test_create_list(self):
        created = {
            "name": "projects/proj1/locations/us/instances/inst1/referenceLists/baddies",
            "description": "detectl_kind:blocklist",
            "entries": [{"value": "evil.com"}],
        }
        adapter, session = make_adapter(
            {("POST", INSTANCE_PATH + "/referenceLists"): FakeResponse(200, created)}
        )
        result = adapter.create_list(ListObject(id=None, name="baddies", kind="blocklist", items=["evil.com"]))
        self.assertEqual(result.items, ["evil.com"])
        create_call = session.calls[0]
        self.assertEqual(create_call[2]["params"]["referenceListId"], "baddies")

    def test_delete_list_unsupported(self):
        adapter, _ = make_adapter({})
        with self.assertRaises(UnsupportedOperationError):
            adapter.delete_list("baddies")

    def test_add_list_items_merges_and_dedupes(self):
        entry = {
            "name": "projects/proj1/locations/us/instances/inst1/referenceLists/baddies",
            "description": "detectl_kind:blocklist",
            "entries": [{"value": "evil.com"}],
        }
        updated = dict(entry, entries=[{"value": "evil.com"}, {"value": "bad.net"}])
        responses = iter([FakeResponse(200, entry), FakeResponse(200, updated)])
        adapter, session = make_adapter(
            {
                ("GET", INSTANCE_PATH + "/referenceLists/baddies"): lambda: next(responses),
                ("PATCH", INSTANCE_PATH + "/referenceLists/baddies"): FakeResponse(200, {}),
            }
        )
        result = adapter.add_list_items("baddies", ["evil.com", "bad.net"])
        self.assertEqual(result.items, ["evil.com", "bad.net"])
        patch_call = [c for c in session.calls if c[0] == "PATCH"][0]
        self.assertEqual(patch_call[2]["json"]["entries"], [{"value": "evil.com"}, {"value": "bad.net"}])

    def test_set_alert_status_unsupported(self):
        adapter, _ = make_adapter({})
        with self.assertRaises(UnsupportedOperationError):
            adapter.set_alert_status("r1:d1", "closed")

    def test_list_alerts_requires_rule_id(self):
        adapter, _ = make_adapter({})
        with self.assertRaises(ValueError):
            adapter.list_alerts()

    def test_list_and_get_alert(self):
        entry = {
            "name": "projects/proj1/locations/us/instances/inst1/rules/r1/detections/d1",
            "type": "RULE_DETECTION",
            "alertState": "ALERTING",
            "timeWindow": {"endTime": "2026-08-14T00:00:00Z"},
        }
        adapter, _ = make_adapter(
            {
                ("GET", INSTANCE_PATH + "/rules/r1/detections"): FakeResponse(200, {"detections": [entry]}),
                ("GET", INSTANCE_PATH + "/rules/r1/detections/d1"): FakeResponse(200, entry),
            }
        )
        alerts = adapter.list_alerts(rule_id="r1")
        self.assertEqual(alerts[0].id, "r1:d1")
        alert = adapter.get_alert("r1:d1")
        self.assertEqual(alert.status, "ALERTING")

    def test_run_query(self):
        data = {"events": [{"udm": {"a": "1"}}, {"udm": {"a": "2"}}]}
        adapter, session = make_adapter({("GET", INSTANCE_PATH + ":udmSearch"): FakeResponse(200, data)})
        result = adapter.run_query('principal.hostname="host1"')
        self.assertEqual(result.rows, [{"a": "1"}, {"a": "2"}])
        get_call = session.calls[0]
        self.assertEqual(get_call[2]["params"]["query"], 'principal.hostname="host1"')
        self.assertIn("time_range.start_time", get_call[2]["params"])


if __name__ == "__main__":
    unittest.main()
