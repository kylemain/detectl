import unittest

from detectl.adapters.sentinel import SentinelAdapter
from detectl.models import ListObject, Rule
from tests.helpers import FakeResponse, FakeSession, multi_route_handler

LOGIN = "https://login.microsoftonline.com"
MGMT = "https://management.azure.com"
LOGANALYTICS = "https://api.loganalytics.io"

WS_PATH = (
    "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.OperationalInsights"
    "/workspaces/ws1/providers/Microsoft.SecurityInsights"
)

TOKEN_ROUTE = {("POST", "/t1/oauth2/v2.0/token"): FakeResponse(200, {"access_token": "tok", "expires_in": 3600})}


def make_adapter(mgmt_routes=None, loganalytics_routes=None):
    routes_by_base = {
        LOGIN: TOKEN_ROUTE,
        MGMT: mgmt_routes or {},
        LOGANALYTICS: loganalytics_routes or {},
    }
    session = FakeSession(multi_route_handler(routes_by_base))
    adapter = SentinelAdapter(
        tenant_id="t1",
        client_id="c1",
        client_secret="s1",
        subscription_id="sub1",
        resource_group="rg1",
        workspace_name="ws1",
        workspace_id="wsid1",
        session=session,
    )
    return adapter, session


class TestSentinelAdapter(unittest.TestCase):
    def test_connection(self):
        adapter, _ = make_adapter()
        self.assertTrue(adapter.test_connection())

    def test_list_rules(self):
        item = {
            "name": "guid1",
            "properties": {"displayName": "Rule1", "query": "SecurityEvent", "severity": "High", "enabled": True, "tactics": ["Persistence"]},
        }
        adapter, _ = make_adapter({("GET", f"{WS_PATH}/alertRules"): FakeResponse(200, {"value": [item]})})
        rules = adapter.list_rules()
        self.assertEqual(rules[0].name, "Rule1")
        self.assertEqual(rules[0].severity, "high")

    def test_list_rules_pagination(self):
        page1 = {"value": [{"name": "g1", "properties": {"displayName": "R1", "query": "q"}}], "nextLink": f"{MGMT}{WS_PATH}/alertRules?page=2"}
        page2 = {"value": [{"name": "g2", "properties": {"displayName": "R2", "query": "q"}}]}
        adapter, _ = make_adapter(
            {
                ("GET", f"{WS_PATH}/alertRules"): FakeResponse(200, page1),
                ("GET", f"{WS_PATH}/alertRules?page=2"): FakeResponse(200, page2),
            }
        )
        rules = adapter.list_rules()
        self.assertEqual(len(rules), 2)

    def test_get_rule(self):
        item = {"name": "guid1", "properties": {"displayName": "Rule1", "query": "q", "severity": "Low", "enabled": True}}
        adapter, _ = make_adapter({("GET", f"{WS_PATH}/alertRules/guid1"): FakeResponse(200, item)})
        rule = adapter.get_rule("guid1")
        self.assertEqual(rule.severity, "low")

    def test_create_and_delete_rule(self):
        item = {"name": "*", "properties": {"displayName": "New", "query": "q", "severity": "Medium", "enabled": True}}
        adapter, session = make_adapter(
            {
                ("PUT", f"{WS_PATH}/alertRules/*"): FakeResponse(200, item),
                ("DELETE", f"{WS_PATH}/alertRules/*"): FakeResponse(200, {}),
            }
        )
        rule = adapter.create_rule(Rule(id=None, name="New", query="q", severity="medium"))
        self.assertEqual(rule.name, "New")
        adapter.delete_rule(rule.id)
        self.assertEqual(session.calls[-1][0], "DELETE")

    def test_set_rule_enabled(self):
        get_item = {"name": "guid1", "properties": {"displayName": "R", "query": "q", "severity": "Medium", "enabled": True, "tactics": []}}
        put_item = {"name": "guid1", "properties": {"displayName": "R", "query": "q", "severity": "Medium", "enabled": False, "tactics": []}}
        adapter, _ = make_adapter(
            {
                ("GET", f"{WS_PATH}/alertRules/guid1"): FakeResponse(200, get_item),
                ("PUT", f"{WS_PATH}/alertRules/guid1"): FakeResponse(200, put_item),
            }
        )
        rule = adapter.disable_rule("guid1")
        self.assertFalse(rule.enabled)

    def test_list_and_get_watchlist(self):
        container_list = {"value": [{"name": "wl1", "properties": {"displayName": "WL1", "description": "d"}}]}
        container = {"name": "wl1", "properties": {"displayName": "WL1", "description": "d"}}
        items = {"value": [{"name": "item1", "properties": {"itemsKeyValue": {"value": "1.2.3.4"}}}]}
        adapter, _ = make_adapter(
            {
                ("GET", f"{WS_PATH}/watchlists"): FakeResponse(200, container_list),
                ("GET", f"{WS_PATH}/watchlists/wl1"): FakeResponse(200, container),
                ("GET", f"{WS_PATH}/watchlists/wl1/watchlistItems"): FakeResponse(200, items),
            }
        )
        lists = adapter.list_lists()
        self.assertEqual(lists[0].kind, "watchlist")
        full = adapter.get_list("wl1")
        self.assertEqual(full.items, ["1.2.3.4"])

    def test_create_list_with_items(self):
        container = {"name": "wl1", "properties": {"displayName": "WL1", "description": ""}}
        items_after = {"value": [{"name": "item1", "properties": {"itemsKeyValue": {"value": "5.6.7.8"}}}]}
        adapter, session = make_adapter(
            {
                ("PUT", f"{WS_PATH}/watchlists/wl1"): FakeResponse(200, {}),
                ("PUT", f"{WS_PATH}/watchlists/wl1/watchlistItems/*"): FakeResponse(200, {}),
                ("GET", f"{WS_PATH}/watchlists/wl1"): FakeResponse(200, container),
                ("GET", f"{WS_PATH}/watchlists/wl1/watchlistItems"): FakeResponse(200, items_after),
            }
        )
        result = adapter.create_list(ListObject(id="wl1", name="WL1", kind="watchlist", items=["5.6.7.8"]))
        self.assertEqual(result.items, ["5.6.7.8"])

    def test_list_alerts_incidents(self):
        item = {"name": "inc1", "properties": {"title": "Incident 1", "severity": "High", "status": "New", "createdTimeUtc": "t"}}
        adapter, _ = make_adapter({("GET", f"{WS_PATH}/incidents"): FakeResponse(200, {"value": [item]})})
        alerts = adapter.list_alerts()
        self.assertEqual(alerts[0].title, "Incident 1")

    def test_set_alert_status(self):
        item = {"name": "inc1", "properties": {"title": "Incident 1", "status": "Closed"}}
        adapter, _ = make_adapter({("PATCH", f"{WS_PATH}/incidents/inc1"): FakeResponse(200, item)})
        alert = adapter.set_alert_status("inc1", "Closed")
        self.assertEqual(alert.status, "Closed")

    def test_run_query_kql(self):
        response = {"tables": [{"columns": [{"name": "Computer"}], "rows": [["host-a"]]}]}
        adapter, _ = make_adapter(loganalytics_routes={("POST", "/v1/workspaces/wsid1/query"): FakeResponse(200, response)})
        result = adapter.run_query("SecurityEvent | take 1")
        self.assertEqual(result.columns, ["Computer"])
        self.assertEqual(result.rows, [{"Computer": "host-a"}])


if __name__ == "__main__":
    unittest.main()
