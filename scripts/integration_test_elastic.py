#!/usr/bin/env python3
"""Cross-repo integration test: Sigma rule -> sigmux -> real Elasticsearch -> detectl.

Unlike the rest of this project's tests (see the README's Testing section),
this one deliberately touches the network and needs a real service: it
proves the sigmux/detectl pairing documented in the README actually works
end to end against a live Elasticsearch, not just that the two projects'
unit tests each pass in isolation.

Steps:
  1. Parse a small Sigma rule and convert it to Elasticsearch Query DSL
     with sigmux -- exactly what `sigmux convert -t elastic` does.
  2. Index a handful of documents into a real Elasticsearch instance, some
     matching the rule and some not.
  3. Run that converted query through detectl's ElasticAdapter.run_query --
     exactly what `detectl -p elastic query "$(cat rule.elastic.json)"` does.
  4. Assert the matching documents come back and the non-matching ones don't.

Requires ELASTICSEARCH_URL (default http://localhost:9200) to be a real,
reachable, security-disabled Elasticsearch instance -- see the
`integration` job in .github/workflows/ci.yml for how CI provides one.
"""
from __future__ import annotations

import os
import sys
import time

import requests

from detectl.adapters.elastic import ElasticAdapter
from sigmux.backends import get_backend
from sigmux.rule import SigmaRule

ES_URL = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
INDEX = "detectl-sigmux-integration-test"

SIGMA_RULE = """
title: Integration Test - Mimikatz Process Execution
logsource: {category: process_creation, product: windows}
detection:
  selection:
    Image|endswith: '\\mimikatz.exe'
  condition: selection
"""

DOCS = [
    {"Image": r"C:\Windows\Temp\mimikatz.exe", "host": "victim-01"},  # should match
    {"Image": r"C:\Tools\x64\mimikatz.exe", "host": "victim-02"},  # should match
    {"Image": r"C:\Windows\System32\notepad.exe", "host": "clean-01"},  # should not match
]


def _wait_for_elasticsearch(timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(f"{ES_URL}/_cluster/health", timeout=5)
            if resp.status_code == 200:
                print(f"Elasticsearch is up: {resp.json().get('status')}")
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise SystemExit(f"Elasticsearch at {ES_URL} never became healthy within {timeout}s")


def _index_docs() -> None:
    requests.delete(f"{ES_URL}/{INDEX}", timeout=10)  # ignore 404 if it doesn't exist yet
    # Elasticsearch's dynamic mapping would map these string fields as
    # analyzed `text` (tokenized, lowercased), and sigmux's wildcard-based
    # DSL assumes exact-value `keyword` fields the same way real Sigma-to-ES
    # tooling does -- without this explicit mapping, the wildcard query
    # below would silently behave unpredictably against analyzed tokens
    # instead of doing the literal endswith match it's supposed to.
    mapping = {"mappings": {"properties": {"Image": {"type": "keyword"}, "host": {"type": "keyword"}}}}
    resp = requests.put(f"{ES_URL}/{INDEX}", json=mapping, timeout=10)
    resp.raise_for_status()
    for i, doc in enumerate(DOCS):
        resp = requests.put(f"{ES_URL}/{INDEX}/_doc/{i}", json=doc, timeout=10)
        resp.raise_for_status()
    resp = requests.post(f"{ES_URL}/{INDEX}/_refresh", timeout=10)
    resp.raise_for_status()


def main():
    print("1. Parsing Sigma rule and converting with sigmux (target: elastic)...")
    rule = SigmaRule.from_yaml(SIGMA_RULE)
    query_dsl = get_backend("elastic").render(rule)
    print(query_dsl)

    print(f"\n2. Waiting for Elasticsearch at {ES_URL} and indexing test documents...")
    _wait_for_elasticsearch()
    _index_docs()

    print("\n3. Running the sigmux-converted query through detectl's ElasticAdapter.run_query...")
    adapter = ElasticAdapter(kibana_base_url="http://unused", api_key="unused", es_base_url=ES_URL)
    result = adapter.run_query(query_dsl, index=INDEX, limit=100)
    matched_hosts = sorted(row["host"] for row in result.rows)

    print(f"\n4. Matched hosts: {matched_hosts}")
    expected = ["victim-01", "victim-02"]
    assert matched_hosts == expected, f"expected {expected}, got {matched_hosts}"
    assert "clean-01" not in matched_hosts, "false positive: matched a non-mimikatz process"

    print("\nPASS: Sigma rule -> sigmux -> real Elasticsearch -> detectl round-trip matched exactly the expected documents.")


if __name__ == "__main__":
    main()
