# detectl

[![CI](https://github.com/kylemain/detectl/actions/workflows/ci.yml/badge.svg)](https://github.com/kylemain/detectl/actions/workflows/ci.yml)

A CLI (and Python library) for managing detection rules, tuning lists
(watchlists, exclusion/allow/block lists, suppression lists, KV stores),
alerts, and ad-hoc queries across multiple SIEM/EDR platforms through one
consistent interface.

```
$ detectl -p splunk rules list
[
  {
    "id": "Suspicious PowerShell Encoded Command",
    "name": "Suspicious PowerShell Encoded Command",
    "query": "index=main process_name IN (\"powershell.exe\", \"pwsh.exe\") AND args=\"*-enc*\"",
    "severity": "high",
    "enabled": true,
    ...
  }
]
```

## Why

Every real detection engineering team ends up managing rules, tuning lists,
and alert triage across more than one platform -- and every platform's API
looks nothing like the others. `detectl` gives each platform a self-contained
adapter behind one shared interface, so the same four resource types (rules,
lists, alerts, queries) work the same way no matter which SIEM you're
pointed at.

This is a from-scratch, clean-room implementation against each platform's
real public REST API -- not a wrapper around any vendor SDK.

## Supported platforms

| Platform | Rules | Lists | Alerts | Ad-hoc query |
|---|---|---|---|---|
| Splunk | Saved searches / correlation searches | KV Store collections | Fired alerts | Blocking search job (SPL) |
| Elastic (Kibana Security + Elasticsearch) | Detection Engine rules | Lists API | Detection signals | Elasticsearch Query DSL |
| Microsoft Sentinel | Scheduled Analytics Rules | Watchlists | Incidents | Log Analytics (KQL) |
| CrowdStrike Falcon | Custom IOA rules | IOC management | Falcon Alerts | Falcon LogScale (LQL) -- optional, see [Known limitations](#known-limitations) |

## Install

```bash
git clone https://github.com/kylemain/detectl.git
cd detectl
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Configure

Copy `examples/config.yml.example` to `~/.detectl/config.yml` and fill in
the platform(s) you use. String values can reference `${ENV_VAR}`, so
secrets never have to live in the file itself:

```yaml
splunk:
  base_url: https://splunk.example.com:8089
  token: ${SPLUNK_TOKEN}
```

Any field you don't set in the config file falls back to a
platform-prefixed environment variable instead (`SPLUNK_BASE_URL`,
`SPLUNK_TOKEN`, `ELASTIC_API_KEY`, `SENTINEL_CLIENT_SECRET`, ...), so you
can skip the config file entirely and configure purely through the
environment if you prefer. See `examples/config.yml.example` for the full
field list per platform.

## Usage

```bash
detectl targets                              # list supported platforms
detectl -p splunk test-connection             # verify credentials

detectl -p elastic rules list
detectl -p elastic rules get <rule_id>
detectl -p elastic rules create -f examples/rules/suspicious_powershell.json
detectl -p elastic rules update <rule_id> -f updated_rule.json
detectl -p elastic rules enable <rule_id>
detectl -p elastic rules delete <rule_id>

detectl -p sentinel lists list --kind watchlist
detectl -p sentinel lists create -f examples/lists/known_bad_ips.json
detectl -p sentinel lists add-items known-bad-ips -i 198.51.100.99
detectl -p sentinel lists remove-items known-bad-ips -i 198.51.100.99

detectl -p crowdstrike alerts list
detectl -p crowdstrike alerts set-status <alert_id> closed

detectl -p sentinel query "SecurityEvent | where EventID == 4625 | take 20"
detectl -p elastic query '{"match": {"process.name": "mimikatz.exe"}}'

# Ad-hoc queries against Falcon run through Falcon LogScale, not the core
# Falcon platform API (see Known limitations) -- requires logscale_url /
# logscale_token in config, in addition to the Falcon client_id/secret.
detectl -p crowdstrike query "#event_simpleName=ProcessRollup2 FileName=mimikatz.exe"
```

Every command prints JSON to stdout, so it composes with `jq` and shell
pipelines the way a real ops CLI should.

### Pairs well with [sigmux](https://github.com/kylemain/sigmux)

sigmux compiles a portable Sigma detection rule into per-platform query
syntax. Its Elasticsearch output is valid Query DSL JSON, so it feeds
directly into `detectl query`:

```bash
sigmux convert my_rule.yml -t elasticsearch -o out/
detectl -p elastic query "$(cat out/my_rule.elasticsearch.json)"
```

The same pairing works for CrowdStrike: sigmux's `logscale` target emits
Falcon LogScale (LQL) query text, which `detectl -p crowdstrike query` now
runs directly -- closing the gap noted below, where the core Falcon
platform API itself has no ad-hoc query surface:

```bash
sigmux convert my_rule.yml -t logscale -o out/
detectl -p crowdstrike query "$(cat out/my_rule.logscale.lql)"
```

## Architecture

- `detectl/models.py` -- canonical, platform-agnostic dataclasses (`Rule`,
  `ListObject`, `Alert`, `QueryResult`). Every adapter converts to/from
  these at its own API boundary; callers only ever see one consistent
  shape. Each model carries a `raw` field with the untouched platform
  payload for anything the common fields don't capture.
- `detectl/adapters/base.py` -- the abstract `SIEMAdapter` interface every
  platform implements, plus a small `HttpMixin` that centralizes HTTP error
  translation (`AuthenticationError`, `NotFoundError`, `APIError`) so
  concrete adapters don't each reimplement it.
- `detectl/adapters/{splunk,elastic,sentinel,crowdstrike}.py` -- one
  self-contained file per platform, each mapping the canonical interface
  onto that platform's real REST API.
- `detectl/config.py` -- per-platform config loading from YAML and/or
  environment variables.
- `detectl/cli.py` -- the click-based CLI wiring the above together.

### Adding a new platform

Implement `SIEMAdapter` (see `detectl/adapters/base.py` for the full
method list) in a new file under `detectl/adapters/`, register it in
`detectl/adapters/__init__.py`'s `REGISTRY`, and add its required config
fields to `detectl/config.py`'s `REQUIRED_FIELDS`/`OPTIONAL_FIELDS`. Not
every platform needs to support every operation -- raise
`UnsupportedOperationError` with a clear explanation rather than faking
support (see Splunk's `set_alert_status`, or CrowdStrike's `run_query` when
Falcon LogScale isn't configured).

## Known limitations

A few platforms don't have a clean native equivalent for one of detectl's
canonical resources. Rather than papering over the mismatch, each adapter
documents its own convention at the top of its file:

- **The core Falcon platform API has no ad-hoc event query endpoint**
  comparable to Splunk SPL, Elasticsearch DSL, or Sentinel KQL -- Falcon
  exposes detections/alerts/IOCs as discrete resources, not a general query
  surface over raw events. `run_query` instead talks to **Falcon LogScale**,
  a genuinely separate CrowdStrike product with its own base URL and its
  own credential (a LogScale Personal API token, distinct from the Falcon
  `client_id`/`client_secret` used for rules/lists/alerts). It's optional:
  configure `logscale_url`/`logscale_token`/`logscale_repository` (see
  `examples/config.yml.example`) to enable it; without them, `run_query`
  raises `UnsupportedOperationError` explaining how to turn it on. LogScale
  query jobs are asynchronous, so `run_query` polls the job (`poll_interval`
  seconds between checks, up to `max_polls` times) until it reports done.
- **Splunk's fired-alerts API has no settable status field** (no ack/close
  concept the way Elastic signals or Sentinel incidents have) --
  `set_alert_status` raises `UnsupportedOperationError`.
- **Kibana's Lists API has no native "kind"** (watchlist vs. exclusion vs.
  allow/block vs. suppression) -- the Elastic adapter stores it in the
  list's `meta.detectl_kind` field as a convention.
- **CrowdStrike's IOC API has no named-list container** at all -- IOCs are
  individually-tagged indicators, so the CrowdStrike adapter groups them
  into named lists via a `detectl_list:{name}` tag, and infers `kind` from
  each IOC's `action` field (allow/block/detect).
- **CrowdStrike custom IOA rules are always scoped to a parent rule
  group** -- there's no bare, group-less rule -- so rule IDs in that
  adapter are encoded as `"{rule_group_id}:{instance_id}"`.
- IOC type inference (`ipv4` / `md5` / `sha1` / `sha256` / `domain`) in the
  CrowdStrike adapter is a heuristic based on the value's shape, not a
  caller-supplied type.

## Testing

No `pytest` dependency -- the whole suite runs on the standard library's
`unittest`. Every adapter test injects a fake `requests.Session` stand-in
(see `tests/helpers.py`) that asserts on exact HTTP calls and returns
canned responses, so the suite never touches the network and needs no
credentials:

```bash
python -m unittest discover -v
```

## License

MIT
