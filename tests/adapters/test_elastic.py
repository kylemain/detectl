import unittest

from detectl.adapters.elastic import ElasticAdapter
from detectl.exceptions import ConfigError, NotFoundError
from detectl.models import ListObject, Rule
from tests.helpers import FakeResponse, FakeSession, route_handler

KIBANA = "https://kibana.test:5601"
ES = "https://es.test:9200"


def make_adapter(routes, default=None, es_base_url=ES):
    session = FakeSession(route_handler(KIBANA, routes, default=default))
    adapter = ElasticAdapter(kibana_base_url=KIBANA, api_key="key", es_base_url=es_base_url, session=session)
    return adapter, session


class TestElasticAdapter(unittest.TestCase):
    def test_connection(self):
        adapter, _ = make_adapter({("GET", "/api/status"): FakeResponse(200, {"status": "ok"})})
        self.assertTrue(adapter.test_connection())

    def test_list_rules(self):
        item = {"id": "r1", "name": "Rule 1", "query": "process.name:*", "severity": "high", "enabled": True, "tags": ["a"]}
        adapter, _ = make_adapter({("GET", "/api/detection_engine/rules/_find"): FakeResponse(200, {"data": [item]})})
        rules = adapter.list_rules()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].name, "Rule 1")

    def test_get_rule(self):
        item = {"id": "r1", "name": "Rule 1", "query": "*", "severity": "low", "enabled": False}
        adapter, _ = make_adapter({("GET", "/api/detection_engine/rules"): FakeResponse(200, item)})
        rule = adapter.get_rule("r1")
        self.assertFalse(rule.enabled)

    def test_create_rule(self):
        item = {"id": "new", "name": "New Rule", "query": "*", "severity": "medium", "enabled": True}
        adapter, session = make_adapter({("POST", "/api/detection_engine/rules"): FakeResponse(200, item)})
        rule = adapter.create_rule(Rule(id=None, name="New Rule", query="*", severity="medium"))
        self.assertEqual(rule.id, "new")

    def test_update_rule(self):
        item = {"id": "r1", "name": "Updated", "query": "*", "severity": "high", "enabled": True}
        adapter, _ = make_adapter({("PUT", "/api/detection_engine/rules"): FakeResponse(200, item)})
        rule = adapter.update_rule("r1", Rule(id="r1", name="Updated", query="*", severity="high"))
        self.assertEqual(rule.name, "Updated")

    def test_delete_rule(self):
        adapter, session = make_adapter({("DELETE", "/api/detection_engine/rules"): FakeResponse(200, {})})
        adapter.delete_rule("r1")
        self.assertEqual(session.calls[-1][0], "DELETE")

    def test_set_rule_enabled(self):
        item = {"id": "r1", "name": "R", "query": "*", "enabled": False}
        adapter, _ = make_adapter({("PATCH", "/api/detection_engine/rules"): FakeResponse(200, item)})
        rule = adapter.disable_rule("r1")
        self.assertFalse(rule.enabled)

    def test_list_lists_with_kind_from_meta(self):
        container = {"id": "l1", "name": "L1", "meta": {"detectl_kind": "exclusion"}}
        adapter, _ = make_adapter({("GET", "/api/lists/_find"): FakeResponse(200, {"data": [container]})})
        result = adapter.list_lists()
        self.assertEqual(result[0].kind, "exclusion")
        self.assertEqual(adapter_kind_filtered := adapter.list_lists(kind="watchlist"), [])

    def test_create_list_with_items(self):
        container = {"id": "l1", "name": "L1", "meta": {"detectl_kind": "watchlist"}}
        adapter, session = make_adapter(
            {
                ("POST", "/api/lists"): FakeResponse(200, container),
                ("POST", "/api/lists/items"): FakeResponse(200, {}),
                ("GET", "/api/lists"): FakeResponse(200, container),
                ("GET", "/api/lists/items/_find"): FakeResponse(200, {"data": [{"value": "1.2.3.4"}]}),
            }
        )
        result = adapter.create_list(ListObject(id=None, name="L1", kind="watchlist", items=["1.2.3.4"]))
        self.assertEqual(result.items, ["1.2.3.4"])

    def test_delete_list(self):
        adapter, session = make_adapter({("DELETE", "/api/lists"): FakeResponse(200, {})})
        adapter.delete_list("l1")
        self.assertEqual(session.calls[-1][0], "DELETE")

    def test_list_alerts(self):
        hit = {
            "_id": "sig1",
            "_source": {"signal": {"rule": {"name": "R", "severity": "high", "id": "r1"}, "status": "open"}, "@timestamp": "t"},
        }
        adapter, _ = make_adapter(
            {("POST", "/api/detection_engine/signals/search"): FakeResponse(200, {"hits": {"hits": [hit]}})}
        )
        alerts = adapter.list_alerts()
        self.assertEqual(alerts[0].id, "sig1")
        self.assertEqual(alerts[0].status, "open")

    def test_get_alert_not_found(self):
        adapter, _ = make_adapter(
            {("POST", "/api/detection_engine/signals/search"): FakeResponse(200, {"hits": {"hits": []}})}
        )
        with self.assertRaises(NotFoundError):
            adapter.get_alert("missing")

    def test_set_alert_status(self):
        hit = {"_id": "sig1", "_source": {"signal": {"rule": {"name": "R"}, "status": "closed"}}}
        adapter, _ = make_adapter(
            {
                ("POST", "/api/detection_engine/signals/status"): FakeResponse(200, {}),
                ("POST", "/api/detection_engine/signals/search"): FakeResponse(200, {"hits": {"hits": [hit]}}),
            }
        )
        alert = adapter.set_alert_status("sig1", "closed")
        self.assertEqual(alert.status, "closed")

    def test_run_query_requires_es_base_url(self):
        adapter, _ = make_adapter({}, es_base_url=None)
        with self.assertRaises(ConfigError):
            adapter.run_query("*")

    def test_run_query_with_dsl_json(self):
        hits = {"hits": {"hits": [{"_id": "1", "_index": "logs", "_source": {"host": "a"}}]}}
        session = FakeSession(route_handler(ES, {("POST", "/*/_search"): FakeResponse(200, hits)}))
        adapter = ElasticAdapter(kibana_base_url=KIBANA, api_key="key", es_base_url=ES, session=session)
        result = adapter.run_query('{"match": {"host": "a"}}')
        self.assertEqual(result.rows[0]["host"], "a")

    def test_run_query_with_bare_string(self):
        hits = {"hits": {"hits": []}}
        session = FakeSession(route_handler(ES, {("POST", "/*/_search"): FakeResponse(200, hits)}))
        adapter = ElasticAdapter(kibana_base_url=KIBANA, api_key="key", es_base_url=ES, session=session)
        result = adapter.run_query("host:a")
        self.assertEqual(result.rows, [])
        body = session.calls[-1][2]["json"]
        self.assertIn("query_string", body["query"])


if __name__ == "__main__":
    unittest.main()
