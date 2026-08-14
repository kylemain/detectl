import base64
import unittest

from detectl.adapters.sumologic import SumoLogicAdapter
from detectl.exceptions import NotFoundError
from detectl.models import ListObject, Rule
from tests.helpers import FakeResponse, FakeSession, route_handler

BASE = "https://api.sumologic.com/api"


def make_adapter(routes, poll_interval=0):
    session = FakeSession(route_handler(BASE, routes))
    adapter = SumoLogicAdapter(
        access_id="id123", access_key="key456", poll_interval=poll_interval, session=session
    )
    return adapter, session


class TestSumoLogicAdapter(unittest.TestCase):
    def test_connection_sends_basic_auth_header(self):
        adapter, session = make_adapter({("GET", "/v1/collectors"): FakeResponse(200, {"collectors": []})})
        self.assertTrue(adapter.test_connection())
        expected = "Basic " + base64.b64encode(b"id123:key456").decode()
        self.assertEqual(session.headers["Authorization"], expected)

    def test_list_and_get_rule(self):
        summary = {"id": "m1", "name": "My Monitor"}
        full = {
            "id": "m1",
            "name": "My Monitor",
            "description": "d",
            "isDisabled": False,
            "queries": [{"rowId": "A", "query": "error"}],
            "tags": {},
        }
        adapter, _ = make_adapter(
            {
                ("GET", "/v1/monitors/search"): FakeResponse(200, {"items": [summary]}),
                ("GET", "/v1/monitors/m1"): FakeResponse(200, full),
            }
        )
        rules = adapter.list_rules()
        self.assertEqual(rules[0].name, "My Monitor")
        rule = adapter.get_rule("m1")
        self.assertEqual(rule.query, "error")
        self.assertTrue(rule.enabled)

    def test_create_rule_requires_parent_id(self):
        adapter, _ = make_adapter({})
        with self.assertRaises(ValueError):
            adapter.create_rule(Rule(id=None, name="new", query="error"))

    def test_create_rule(self):
        created = {"id": "m2", "name": "new", "queries": [{"rowId": "A", "query": "error"}], "isDisabled": False}
        adapter, session = make_adapter({("POST", "/v1/monitors"): FakeResponse(200, created)})
        rule = adapter.create_rule(Rule(id=None, name="new", query="error", raw={"parent_id": "folder1"}))
        self.assertEqual(rule.name, "new")
        post_call = session.calls[0]
        self.assertEqual(post_call[2]["params"]["parentId"], "folder1")

    def test_delete_rule(self):
        adapter, session = make_adapter({("DELETE", "/v1/monitors/m1"): FakeResponse(200, {})})
        adapter.delete_rule("m1")
        self.assertEqual(session.calls[-1][0], "DELETE")

    def test_set_rule_enabled_reads_then_writes(self):
        current = {"id": "m1", "name": "m", "isDisabled": True, "queries": []}
        updated = {"id": "m1", "name": "m", "isDisabled": False, "queries": []}
        responses = iter([FakeResponse(200, current), FakeResponse(200, updated)])
        adapter, session = make_adapter(
            {
                ("GET", "/v1/monitors/m1"): lambda: next(responses),
                ("PUT", "/v1/monitors/m1"): FakeResponse(200, {}),
            }
        )
        rule = adapter.enable_rule("m1")
        self.assertTrue(rule.enabled)
        put_call = [c for c in session.calls if c[0] == "PUT"][0]
        self.assertEqual(put_call[2]["json"]["isDisabled"], False)
        self.assertEqual(put_call[2]["json"]["id"], "")

    def test_list_lists_kind_from_description_tag(self):
        entry = {"id": "l1", "name": "baddies", "description": "IR confirmed detectl_kind:blocklist"}
        adapter, _ = make_adapter(
            {("GET", "/sec/v1/match-lists"): FakeResponse(200, {"data": {"objects": [entry]}})}
        )
        lists = adapter.list_lists()
        self.assertEqual(lists[0].kind, "blocklist")

    def test_list_lists_filters_by_kind(self):
        entries = [
            {"id": "a", "name": "a", "description": "detectl_kind:blocklist"},
            {"id": "b", "name": "b", "description": "detectl_kind:watchlist"},
        ]
        adapter, _ = make_adapter(
            {("GET", "/sec/v1/match-lists"): FakeResponse(200, {"data": {"objects": entries}})}
        )
        self.assertEqual([r.name for r in adapter.list_lists(kind="watchlist")], ["b"])

    def test_get_list_with_paginated_items(self):
        entry = {"id": "l1", "name": "baddies", "description": "detectl_kind:blocklist"}
        page1 = {"data": {"objects": [{"id": "i1", "value": "1.2.3.4"}], "nextPageToken": "tok2"}}
        page2 = {"data": {"objects": [{"id": "i2", "value": "5.6.7.8"}], "nextPageToken": ""}}
        responses = iter([FakeResponse(200, page1), FakeResponse(200, page2)])
        adapter, _ = make_adapter(
            {
                ("GET", "/sec/v1/match-lists/l1"): FakeResponse(200, {"data": entry}),
                ("GET", "/sec/v1/match-list-items/all"): lambda: next(responses),
            }
        )
        result = adapter.get_list("l1")
        self.assertEqual(result.items, ["1.2.3.4", "5.6.7.8"])

    def test_create_list_with_items(self):
        created = {"id": "l1", "name": "baddies", "description": "detectl_kind:blocklist"}
        adapter, session = make_adapter(
            {
                ("POST", "/sec/v1/match-lists"): FakeResponse(200, {"data": created}),
                ("POST", "/sec/v1/match-lists/l1/items"): FakeResponse(200, {}),
                ("GET", "/sec/v1/match-lists/l1"): FakeResponse(200, {"data": created}),
                ("GET", "/sec/v1/match-list-items/all"): FakeResponse(
                    200, {"data": {"objects": [{"id": "i1", "value": "evil.com"}], "nextPageToken": ""}}
                ),
            }
        )
        result = adapter.create_list(ListObject(id=None, name="baddies", kind="blocklist", items=["evil.com"]))
        self.assertEqual(result.items, ["evil.com"])
        create_call = session.calls[0]
        self.assertEqual(create_call[2]["json"]["fields"]["targetColumn"], "Other")

    def test_delete_list(self):
        adapter, session = make_adapter({("DELETE", "/sec/v1/match-lists/l1"): FakeResponse(200, {})})
        adapter.delete_list("l1")
        self.assertEqual(session.calls[-1][0], "DELETE")

    def test_remove_list_items_resolves_ids_first(self):
        entry = {"id": "l1", "name": "baddies", "description": ""}
        adapter, session = make_adapter(
            {
                ("GET", "/sec/v1/match-list-items/all"): FakeResponse(
                    200, {"data": {"objects": [{"id": "i1", "value": "evil.com"}], "nextPageToken": ""}}
                ),
                ("POST", "/sec/v1/match-list-items/bulk-delete"): FakeResponse(200, {}),
                ("GET", "/sec/v1/match-lists/l1"): FakeResponse(200, {"data": entry}),
            }
        )
        adapter.remove_list_items("l1", ["evil.com"])
        bulk_call = [c for c in session.calls if c[1].endswith("/bulk-delete")][0]
        self.assertEqual(bulk_call[2]["json"], {"ids": ["i1"]})

    def test_list_and_get_alert(self):
        entry = {"id": "in1", "name": "Insight 1", "severity": "high", "status": "new", "ruleId": "r1"}
        adapter, _ = make_adapter(
            {
                ("GET", "/sec/v2/insights"): FakeResponse(200, {"data": {"objects": [entry]}}),
                ("GET", "/sec/v2/insights/in1"): FakeResponse(200, {"data": entry}),
            }
        )
        alerts = adapter.list_alerts()
        self.assertEqual(alerts[0].rule_id, "r1")
        alert = adapter.get_alert("in1")
        self.assertEqual(alert.title, "Insight 1")

    def test_get_alert_not_found(self):
        adapter, _ = make_adapter({("GET", "/sec/v2/insights/missing"): FakeResponse(200, {"data": {}})})
        with self.assertRaises(NotFoundError):
            adapter.get_alert("missing")

    def test_set_alert_status(self):
        entry = {"id": "in1", "name": "Insight 1", "status": "closed"}
        adapter, session = make_adapter(
            {
                ("PUT", "/sec/v2/insights/in1/status"): FakeResponse(200, {}),
                ("GET", "/sec/v2/insights/in1"): FakeResponse(200, {"data": entry}),
            }
        )
        alert = adapter.set_alert_status("in1", "closed")
        self.assertEqual(alert.status, "closed")

    def test_run_query_immediate_complete(self):
        adapter, session = make_adapter(
            {
                ("POST", "/v1/search/jobs"): FakeResponse(200, {"id": "j1"}),
                ("GET", "/v1/search/jobs/j1"): FakeResponse(200, {"state": "DONE GATHERING RESULTS"}),
                ("GET", "/v1/search/jobs/j1/messages"): FakeResponse(200, {"messages": [{"map": {"a": "1"}}]}),
            }
        )
        result = adapter.run_query("error")
        self.assertEqual(result.rows, [{"a": "1"}])
        self.assertEqual(result.columns, ["a"])

    def test_run_query_polls_until_done(self):
        responses = iter(
            [
                FakeResponse(200, {"state": "GATHERING RESULTS"}),
                FakeResponse(200, {"state": "DONE GATHERING RESULTS"}),
            ]
        )
        adapter, session = make_adapter(
            {
                ("POST", "/v1/search/jobs"): FakeResponse(200, {"id": "j1"}),
                ("GET", "/v1/search/jobs/j1"): lambda: next(responses),
                ("GET", "/v1/search/jobs/j1/messages"): FakeResponse(200, {"messages": [{"map": {"x": "1"}}]}),
            }
        )
        result = adapter.run_query("error")
        self.assertEqual(result.rows, [{"x": "1"}])

    def test_run_query_stops_after_max_polls(self):
        adapter, session = make_adapter(
            {
                ("POST", "/v1/search/jobs"): FakeResponse(200, {"id": "j1"}),
                ("GET", "/v1/search/jobs/j1"): FakeResponse(200, {"state": "GATHERING RESULTS"}),
                ("GET", "/v1/search/jobs/j1/messages"): FakeResponse(200, {"messages": []}),
            }
        )
        adapter.max_polls = 2
        result = adapter.run_query("error")
        self.assertEqual(result.rows, [])


if __name__ == "__main__":
    unittest.main()
