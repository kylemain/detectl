import unittest

from detectl.adapters.qradar import QRadarAdapter
from detectl.exceptions import UnsupportedOperationError
from detectl.models import ListObject, Rule
from tests.helpers import FakeResponse, FakeSession, route_handler

BASE = "https://qradar.example.com"


def make_adapter(routes, poll_interval=0):
    session = FakeSession(route_handler(BASE, routes))
    adapter = QRadarAdapter(base_url=BASE, token="tok", poll_interval=poll_interval, session=session)
    return adapter, session


class TestQRadarAdapter(unittest.TestCase):
    def test_connection_sends_sec_and_version_headers(self):
        adapter, session = make_adapter({("GET", "/api/system/about"): FakeResponse(200, {})})
        self.assertTrue(adapter.test_connection())
        self.assertEqual(session.headers["SEC"], "tok")
        self.assertEqual(session.headers["Version"], "21.0")

    def test_list_and_get_rule(self):
        entry = {"id": 5, "name": "Suspicious Login", "enabled": True, "type": "EVENT"}
        adapter, _ = make_adapter(
            {
                ("GET", "/api/analytics/rules"): FakeResponse(200, [entry]),
                ("GET", "/api/analytics/rules/5"): FakeResponse(200, entry),
            }
        )
        rules = adapter.list_rules()
        self.assertEqual(rules[0].id, "5")
        rule = adapter.get_rule("5")
        self.assertEqual(rule.name, "Suspicious Login")
        self.assertTrue(rule.enabled)

    def test_create_rule_unsupported(self):
        adapter, _ = make_adapter({})
        with self.assertRaises(UnsupportedOperationError):
            adapter.create_rule(Rule(id=None, name="new", query=""))

    def test_update_rule_unsupported(self):
        adapter, _ = make_adapter({})
        with self.assertRaises(UnsupportedOperationError):
            adapter.update_rule("5", Rule(id="5", name="new", query=""))

    def test_delete_rule(self):
        adapter, session = make_adapter({("DELETE", "/api/analytics/rules/5"): FakeResponse(200, {})})
        adapter.delete_rule("5")
        self.assertEqual(session.calls[-1][0], "DELETE")

    def test_set_rule_enabled(self):
        entry = {"id": 5, "name": "r", "enabled": False}
        adapter, session = make_adapter({("POST", "/api/analytics/rules/5"): FakeResponse(200, entry)})
        rule = adapter.disable_rule("5")
        self.assertFalse(rule.enabled)
        self.assertEqual(session.calls[-1][2]["json"], {"enabled": False})

    def test_list_lists_kind_from_description_tag(self):
        entry = {"name": "baddies", "description": "IR-confirmed detectl_kind:blocklist", "data": [{"value": "1.2.3.4"}]}
        adapter, _ = make_adapter({("GET", "/api/reference_data/sets"): FakeResponse(200, [entry])})
        lists = adapter.list_lists()
        self.assertEqual(lists[0].kind, "blocklist")
        self.assertEqual(lists[0].items, ["1.2.3.4"])

    def test_list_lists_defaults_kind_when_untagged(self):
        entry = {"name": "misc", "description": "no tag here", "data": []}
        adapter, _ = make_adapter({("GET", "/api/reference_data/sets"): FakeResponse(200, [entry])})
        self.assertEqual(adapter.list_lists()[0].kind, "watchlist")

    def test_list_lists_filters_by_kind(self):
        entries = [
            {"name": "a", "description": "detectl_kind:blocklist", "data": []},
            {"name": "b", "description": "detectl_kind:watchlist", "data": []},
        ]
        adapter, _ = make_adapter({("GET", "/api/reference_data/sets"): FakeResponse(200, entries)})
        self.assertEqual([r.name for r in adapter.list_lists(kind="watchlist")], ["b"])

    def test_get_list(self):
        entry = {"name": "baddies", "description": "detectl_kind:blocklist", "data": [{"value": "evil.com"}]}
        adapter, _ = make_adapter({("GET", "/api/reference_data/sets/baddies"): FakeResponse(200, entry)})
        result = adapter.get_list("baddies")
        self.assertEqual(result.items, ["evil.com"])

    def test_create_list_with_items(self):
        entry = {"name": "baddies", "description": "detectl_kind:blocklist", "data": [{"value": "evil.com"}]}
        adapter, session = make_adapter(
            {
                ("POST", "/api/reference_data/sets"): FakeResponse(201, {}),
                ("POST", "/api/reference_data/sets/baddies"): FakeResponse(201, {}),
                ("GET", "/api/reference_data/sets/baddies"): FakeResponse(200, entry),
            }
        )
        result = adapter.create_list(ListObject(id=None, name="baddies", kind="blocklist", items=["evil.com"]))
        self.assertEqual(result.items, ["evil.com"])
        create_call = session.calls[0]
        self.assertEqual(create_call[2]["params"]["description"], "detectl_kind:blocklist")

    def test_delete_list(self):
        adapter, session = make_adapter({("DELETE", "/api/reference_data/sets/baddies"): FakeResponse(200, {})})
        adapter.delete_list("baddies")
        self.assertEqual(session.calls[-1][0], "DELETE")

    def test_remove_list_items(self):
        adapter, session = make_adapter(
            {
                ("DELETE", "/api/reference_data/sets/baddies/evil.com"): FakeResponse(200, {}),
                ("GET", "/api/reference_data/sets/baddies"): FakeResponse(
                    200, {"name": "baddies", "description": "", "data": []}
                ),
            }
        )
        adapter.remove_list_items("baddies", ["evil.com"])
        deletes = [c for c in session.calls if c[0] == "DELETE"]
        self.assertEqual(len(deletes), 1)

    def test_list_and_get_alert(self):
        entry = {"id": 42, "description": "Offense 42", "severity": 7, "status": "OPEN", "rules": [{"id": 5}]}
        adapter, _ = make_adapter(
            {
                ("GET", "/api/siem/offenses"): FakeResponse(200, [entry]),
                ("GET", "/api/siem/offenses/42"): FakeResponse(200, entry),
            }
        )
        alerts = adapter.list_alerts()
        self.assertEqual(alerts[0].rule_id, "5")
        alert = adapter.get_alert("42")
        self.assertEqual(alert.title, "Offense 42")

    def test_set_alert_status(self):
        entry = {"id": 42, "description": "Offense 42", "status": "CLOSED"}
        adapter, session = make_adapter({("POST", "/api/siem/offenses/42"): FakeResponse(200, entry)})
        alert = adapter.set_alert_status("42", "CLOSED")
        self.assertEqual(alert.status, "CLOSED")
        self.assertEqual(session.calls[-1][2]["params"], {"status": "CLOSED"})

    def test_run_query_immediate_complete(self):
        adapter, session = make_adapter(
            {
                ("POST", "/api/ariel/searches"): FakeResponse(200, {"search_id": "s1"}),
                ("GET", "/api/ariel/searches/s1"): FakeResponse(200, {"status": "COMPLETED"}),
                ("GET", "/api/ariel/searches/s1/results"): FakeResponse(200, {"events": [{"a": "1"}]}),
            }
        )
        result = adapter.run_query("SELECT * FROM events")
        self.assertEqual(result.rows, [{"a": "1"}])

    def test_run_query_polls_until_completed(self):
        responses = iter(
            [
                FakeResponse(200, {"status": "WAIT STATE"}),
                FakeResponse(200, {"status": "COMPLETED"}),
            ]
        )
        adapter, session = make_adapter(
            {
                ("POST", "/api/ariel/searches"): FakeResponse(200, {"search_id": "s1"}),
                ("GET", "/api/ariel/searches/s1"): lambda: next(responses),
                ("GET", "/api/ariel/searches/s1/results"): FakeResponse(200, {"events": [{"x": "1"}]}),
            }
        )
        result = adapter.run_query("SELECT * FROM events")
        self.assertEqual(result.rows, [{"x": "1"}])

    def test_run_query_stops_after_max_polls(self):
        adapter, session = make_adapter(
            {
                ("POST", "/api/ariel/searches"): FakeResponse(200, {"search_id": "s1"}),
                ("GET", "/api/ariel/searches/s1"): FakeResponse(200, {"status": "WAIT STATE"}),
                ("GET", "/api/ariel/searches/s1/results"): FakeResponse(200, {"events": []}),
            }
        )
        adapter.max_polls = 2
        result = adapter.run_query("SELECT * FROM events")
        self.assertEqual(result.rows, [])

    def test_run_query_respects_limit(self):
        events = [{"i": str(i)} for i in range(5)]
        adapter, session = make_adapter(
            {
                ("POST", "/api/ariel/searches"): FakeResponse(200, {"search_id": "s1"}),
                ("GET", "/api/ariel/searches/s1"): FakeResponse(200, {"status": "COMPLETED"}),
                ("GET", "/api/ariel/searches/s1/results"): FakeResponse(200, {"events": events}),
            }
        )
        result = adapter.run_query("SELECT * FROM events", limit=2)
        self.assertEqual(len(result.rows), 2)


if __name__ == "__main__":
    unittest.main()
