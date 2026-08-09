import unittest

from detectl.adapters.splunk import SplunkAdapter
from detectl.exceptions import NotFoundError, UnsupportedOperationError
from detectl.models import ListObject, Rule
from tests.helpers import FakeResponse, FakeSession, route_handler

BASE = "https://splunk.test:8089"
NS_SUFFIX = "/servicesNS/nobody/search"


def p(path: str) -> str:
    return NS_SUFFIX + path


def make_adapter(routes, default=None):
    session = FakeSession(route_handler(BASE, routes, default=default))
    adapter = SplunkAdapter(base_url=BASE, token="tok", session=session)
    return adapter, session


class TestSplunkAdapter(unittest.TestCase):
    def test_connection(self):
        adapter, _ = make_adapter({("GET", "/services/server/info"): FakeResponse(200, {"ok": True})})
        self.assertTrue(adapter.test_connection())

    def test_list_rules(self):
        entry = {"name": "r1", "content": {"search": "index=main", "description": "d", "disabled": "0"}}
        adapter, _ = make_adapter({("GET", p("/saved/searches")): FakeResponse(200, {"entry": [entry]})})
        rules = adapter.list_rules()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].name, "r1")
        self.assertTrue(rules[0].enabled)

    def test_get_rule(self):
        entry = {"name": "r1", "content": {"search": "index=main", "disabled": "1"}}
        adapter, _ = make_adapter({("GET", p("/saved/searches/r1")): FakeResponse(200, {"entry": [entry]})})
        rule = adapter.get_rule("r1")
        self.assertEqual(rule.query, "index=main")
        self.assertFalse(rule.enabled)

    def test_create_rule(self):
        entry = {"name": "newrule", "content": {"search": "index=x", "disabled": "0"}}
        adapter, session = make_adapter(
            {
                ("POST", p("/saved/searches")): FakeResponse(201, {}),
                ("GET", p("/saved/searches/newrule")): FakeResponse(200, {"entry": [entry]}),
            }
        )
        rule = adapter.create_rule(Rule(id=None, name="newrule", query="index=x"))
        self.assertEqual(rule.name, "newrule")
        self.assertEqual(session.calls[0][0], "POST")

    def test_update_rule(self):
        entry = {"name": "r1", "content": {"search": "index=y", "disabled": "0"}}
        adapter, _ = make_adapter(
            {
                ("POST", p("/saved/searches/r1")): FakeResponse(200, {}),
                ("GET", p("/saved/searches/r1")): FakeResponse(200, {"entry": [entry]}),
            }
        )
        rule = adapter.update_rule("r1", Rule(id="r1", name="r1", query="index=y"))
        self.assertEqual(rule.query, "index=y")

    def test_delete_rule(self):
        adapter, session = make_adapter({("DELETE", p("/saved/searches/r1")): FakeResponse(200, {})})
        adapter.delete_rule("r1")
        self.assertEqual(session.calls[-1][0], "DELETE")

    def test_enable_disable_rule(self):
        entry = {"name": "r1", "content": {"search": "index=z", "disabled": "0"}}
        adapter, _ = make_adapter(
            {
                ("POST", p("/saved/searches/r1/enable")): FakeResponse(200, {}),
                ("POST", p("/saved/searches/r1/disable")): FakeResponse(200, {}),
                ("GET", p("/saved/searches/r1")): FakeResponse(200, {"entry": [entry]}),
            }
        )
        self.assertEqual(adapter.enable_rule("r1").name, "r1")
        self.assertEqual(adapter.disable_rule("r1").name, "r1")

    def test_list_lists_kv_store(self):
        entry = {"name": "mylist"}
        adapter, _ = make_adapter({("GET", p("/storage/collections/config")): FakeResponse(200, {"entry": [entry]})})
        result = adapter.list_lists()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].kind, "kv_store")

    def test_list_lists_wrong_kind_returns_empty(self):
        adapter, _ = make_adapter({})
        self.assertEqual(adapter.list_lists(kind="watchlist"), [])

    def test_create_list_and_add_items(self):
        records = [{"_key": "1", "value": "1.2.3.4"}]
        adapter, session = make_adapter(
            {
                ("POST", p("/storage/collections/config")): FakeResponse(201, {}),
                ("POST", p("/storage/collections/data/mylist")): FakeResponse(201, {"_key": "1"}),
                ("GET", p("/storage/collections/config/mylist")): FakeResponse(200, {"entry": [{"name": "mylist"}]}),
                ("GET", p("/storage/collections/data/mylist")): FakeResponse(200, records),
            }
        )
        result = adapter.create_list(ListObject(id=None, name="mylist", kind="kv_store", items=["1.2.3.4"]))
        self.assertEqual(result.items, ["1.2.3.4"])

    def test_remove_list_items(self):
        records = [{"_key": "1", "value": "1.2.3.4"}, {"_key": "2", "value": "5.6.7.8"}]
        adapter, session = make_adapter(
            {
                ("GET", p("/storage/collections/data/mylist")): FakeResponse(200, records),
                ("DELETE", p("/storage/collections/data/mylist/1")): FakeResponse(200, {}),
                ("GET", p("/storage/collections/config/mylist")): FakeResponse(200, {"entry": [{"name": "mylist"}]}),
            }
        )
        adapter.remove_list_items("mylist", ["1.2.3.4"])
        deletes = [c for c in session.calls if c[0] == "DELETE"]
        self.assertEqual(len(deletes), 1)

    def test_list_alerts(self):
        groups = {"entry": [{"name": "group1"}]}
        instances = {"entry": [{"name": "inst1", "content": {"severity": "high", "trigger_time": "t"}}]}
        adapter, _ = make_adapter(
            {
                ("GET", p("/alerts/fired_alerts")): FakeResponse(200, groups),
                ("GET", p("/alerts/fired_alerts/group1")): FakeResponse(200, instances),
            }
        )
        result = adapter.list_alerts()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].id, "group1:inst1")

    def test_set_alert_status_unsupported(self):
        adapter, _ = make_adapter({})
        with self.assertRaises(UnsupportedOperationError):
            adapter.set_alert_status("group1:inst1", "closed")

    def test_run_query(self):
        job = {"sid": "123"}
        results = {"results": [{"host": "a"}], "fields": [{"name": "host"}]}
        adapter, session = make_adapter(
            {
                ("POST", p("/search/jobs")): FakeResponse(201, job),
                ("GET", p("/search/jobs/123/results")): FakeResponse(200, results),
            }
        )
        result = adapter.run_query("index=main")
        self.assertEqual(result.columns, ["host"])
        self.assertEqual(result.rows, [{"host": "a"}])
        # search text should have been auto-prefixed with "search "
        post_call = [c for c in session.calls if c[0] == "POST" and c[1].endswith("/search/jobs")][0]
        self.assertEqual(post_call[2]["data"]["search"], "search index=main")

    def test_get_alert_not_found(self):
        instances = {"entry": []}
        adapter, _ = make_adapter({("GET", p("/alerts/fired_alerts/group1")): FakeResponse(200, instances)})
        with self.assertRaises(NotFoundError):
            adapter.get_alert("group1:missing")


if __name__ == "__main__":
    unittest.main()
