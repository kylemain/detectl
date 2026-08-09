import unittest

from detectl.adapters.crowdstrike import CrowdStrikeAdapter
from detectl.exceptions import NotFoundError, UnsupportedOperationError
from detectl.models import ListObject, Rule
from tests.helpers import FakeResponse, FakeSession, route_handler

BASE = "https://api.crowdstrike.com"
TOKEN_ROUTE = {("POST", "/oauth2/token"): FakeResponse(200, {"access_token": "tok", "expires_in": 1800})}


def make_adapter(routes):
    all_routes = {**TOKEN_ROUTE, **routes}
    session = FakeSession(route_handler(BASE, all_routes))
    adapter = CrowdStrikeAdapter(client_id="id", client_secret="secret", session=session)
    return adapter, session


class TestCrowdStrikeAdapter(unittest.TestCase):
    def test_connection(self):
        adapter, _ = make_adapter({})
        self.assertTrue(adapter.test_connection())

    def test_list_rules_requires_group_id(self):
        adapter, _ = make_adapter({})
        with self.assertRaises(ValueError):
            adapter.list_rules()

    def test_list_and_get_rule(self):
        group = {
            "resources": [
                {
                    "id": "g1",
                    "rules": [
                        {"instance_id": "r1", "name": "Rule1", "field_values": [{"name": "image", "value": "*.exe"}], "pattern_severity": "high", "enabled": True}
                    ],
                }
            ]
        }
        adapter, _ = make_adapter({("GET", "/ioarules/entities/rule-groups/v1"): FakeResponse(200, group)})
        rules = adapter.list_rules(rule_group_id="g1")
        self.assertEqual(rules[0].id, "g1:r1")
        rule = adapter.get_rule("g1:r1")
        self.assertEqual(rule.name, "Rule1")

    def test_get_rule_not_found(self):
        group = {"resources": [{"id": "g1", "rules": []}]}
        adapter, _ = make_adapter({("GET", "/ioarules/entities/rule-groups/v1"): FakeResponse(200, group)})
        with self.assertRaises(NotFoundError):
            adapter.get_rule("g1:missing")

    def test_create_rule(self):
        create_resp = {"resources": [{"instance_id": "new1"}]}
        group = {"resources": [{"id": "g1", "rules": [{"instance_id": "new1", "name": "New", "field_values": [], "enabled": True}]}]}
        adapter, session = make_adapter(
            {
                ("POST", "/ioarules/entities/rules/v1"): FakeResponse(200, create_resp),
                ("GET", "/ioarules/entities/rule-groups/v1"): FakeResponse(200, group),
            }
        )
        rule = adapter.create_rule(Rule(id=None, name="New", query="[]", raw={"rule_group_id": "g1"}))
        self.assertEqual(rule.id, "g1:new1")

    def test_create_rule_requires_group_id(self):
        adapter, _ = make_adapter({})
        with self.assertRaises(ValueError):
            adapter.create_rule(Rule(id=None, name="New", query="[]"))

    def test_delete_rule(self):
        adapter, session = make_adapter({("DELETE", "/ioarules/entities/rules/v1"): FakeResponse(200, {})})
        adapter.delete_rule("g1:r1")
        self.assertEqual(session.calls[-1][0], "DELETE")

    def test_list_lists_and_get(self):
        ids_resp = {"resources": ["ioc1"]}
        details_resp = {
            "resources": [
                {"id": "ioc1", "value": "1.2.3.4", "action": "block", "tags": ["detectl_list:baddies"]}
            ]
        }
        adapter, _ = make_adapter(
            {
                ("GET", "/iocs/queries/indicators/v1"): FakeResponse(200, ids_resp),
                ("GET", "/iocs/entities/indicators/v1"): FakeResponse(200, details_resp),
            }
        )
        lists = adapter.list_lists()
        self.assertEqual(lists[0].kind, "blocklist")
        result = adapter.get_list("baddies")
        self.assertEqual(result.items, ["1.2.3.4"])

    def test_get_list_not_found(self):
        adapter, _ = make_adapter({("GET", "/iocs/queries/indicators/v1"): FakeResponse(200, {"resources": []})})
        with self.assertRaises(NotFoundError):
            adapter.get_list("nope")

    def test_create_list(self):
        adapter, session = make_adapter(
            {
                ("POST", "/iocs/entities/indicators/v1"): FakeResponse(200, {}),
                ("GET", "/iocs/queries/indicators/v1"): FakeResponse(200, {"resources": ["ioc1"]}),
                ("GET", "/iocs/entities/indicators/v1"): FakeResponse(
                    200, {"resources": [{"id": "ioc1", "value": "evil.com", "action": "block", "tags": ["detectl_list:baddies"]}]}
                ),
            }
        )
        result = adapter.create_list(ListObject(id=None, name="baddies", kind="blocklist", items=["evil.com"]))
        self.assertEqual(result.items, ["evil.com"])

    def test_list_alerts(self):
        ids_resp = {"resources": ["a1"]}
        details_resp = {"resources": [{"composite_id": "a1", "display_name": "Alert 1", "severity_name": "High", "status": "new"}]}
        adapter, _ = make_adapter(
            {
                ("GET", "/alerts/queries/alerts/v2"): FakeResponse(200, ids_resp),
                ("POST", "/alerts/entities/alerts/v2"): FakeResponse(200, details_resp),
            }
        )
        alerts = adapter.list_alerts()
        self.assertEqual(alerts[0].title, "Alert 1")

    def test_set_alert_status(self):
        details_resp = {"resources": [{"composite_id": "a1", "display_name": "Alert 1", "status": "closed"}]}
        # set_alert_status PATCHes then calls get_alert, which POSTs -- register both.
        adapter, _ = make_adapter(
            {
                ("PATCH", "/alerts/entities/alerts/v2"): FakeResponse(200, {}),
                ("POST", "/alerts/entities/alerts/v2"): FakeResponse(200, details_resp),
            }
        )
        alert = adapter.set_alert_status("a1", "closed")
        self.assertEqual(alert.status, "closed")

    def test_run_query_unsupported(self):
        adapter, _ = make_adapter({})
        with self.assertRaises(UnsupportedOperationError):
            adapter.run_query("anything")


if __name__ == "__main__":
    unittest.main()
