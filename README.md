# detectl

[![CI](https://github.com/kylemain/detectl/actions/workflows/ci.yml/badge.svg)](https://github.com/kylemain/detectl/actions/workflows/ci.yml)
[![coverage](coverage.svg)](#testing)
[![PyPI](https://img.shields.io/pypi/v/detectl)](https://pypi.org/project/detectl/)

A CLI (and Python library) for managing detection rules, tuning lists
(watchlists, exclusion/allow/block lists, suppression lists, KV stores),
alerts, and ad-hoc queries across multiple SIEM/EDR platforms through one
consistent interface.

This is the same kind of cross-platform detection tuning work I do professionally -- one consistent interface instead of re-learning seven platforms' APIs -- built clean-room, not tied to any employer's internal tooling. It pairs directly with [sigmux](https://github.com/kylemain/sigmux), which converts a portable Sigma rule into whichever query language a given platform speaks; detectl takes it the rest of the way and actually pushes it live. See [Pairs well with sigmux](#pairs-well-with-sigmux) below.

![sigmux and detectl demo](demo.gif)

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
| IBM QRadar | CRE rule metadata (enable/disable/delete only) | Reference Data Sets | Offenses | Ariel Query Language (AQL) |
| Sumo Logic | Monitors Library | Cloud SIEM Match Lists | Cloud SIEM Insights | Search Job API |
| Google Chronicle (Google SecOps) | Rules (YARA-L text) | Reference Lists (no delete -- see [Known limitations](#known-limitations)) | Detections (rule-scoped, read-only) | UDM Search |

## Install

Published on PyPI. In a fresh terminal, with no prior setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install "detectl[sigma,dryrun]"
```

The quotes matter -- without them, zsh (macOS's default shell) treats `[...]` as a glob pattern and errors instead of installing. `sigma` pulls in [sigmux](https://github.com/kylemain/sigmux) (for `rules create-from-sigma`); `dryrun` pulls in `rich` (for `--dry-run`'s diff view). Both are optional -- plain `pip install detectl` works fine for everything else. And `pip install detectl` alone, outside a venv, will likely be refused on a modern Mac -- recent Python installs block bare system-wide installs on purpose, which the two lines above sidestep.

Prefer [pipx](https://pipx.pypa.io) and don't want to think about venvs at all: `pipx install "detectl[sigma,dryrun]"` (one command, isolation handled automatically).

The Usage examples below reference files under `examples/`, so to run them verbatim, clone the repo instead and install in editable mode:

```bash
git clone https://github.com/kylemain/detectl.git
cd detectl
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[sigma,dryrun]"
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

detectl -p qradar rules list
detectl -p qradar lists create -f examples/lists/malicious_domains.json
detectl -p qradar alerts list
detectl -p qradar query "SELECT UTF8(payload) AS payload FROM events WHERE sourceip='10.0.0.5'"

detectl -p sumologic rules create -f examples/rules/c2_beacon_suspicious_port.json
detectl -p sumologic lists list --kind blocklist
detectl -p sumologic query "error | count by sourcehost"

detectl -p chronicle rules create -f examples/rules/mimikatz_credential_dumping.json
detectl -p chronicle lists create -f examples/lists/vip_watchlist_usernames.json
detectl -p chronicle query 'principal.hostname="host1" and target.process.file.full_path contains "mimikatz.exe"'
```

Every command prints JSON to stdout, so it composes with `jq` and shell
pipelines the way a real ops CLI should.

### Pairs well with [sigmux](https://github.com/kylemain/sigmux)

sigmux compiles a portable Sigma detection rule into per-platform query syntax, and its target names match detectl's platform names 1:1 on purpose (`elastic`, `crowdstrike`, `sentinel`, `splunk`, `qradar`, `sumologic`, `chronicle`). detectl imports sigmux as a library (the `sigma` extra) to fold "convert, then create" into one step.

Try it right now, no credentials or config needed -- grab a real example rule and run it with `--dry-run`, which shows the full converted query and rule metadata (Terraform-plan style) without touching any platform:

```bash
curl -o mimikatz.yml https://raw.githubusercontent.com/kylemain/sigmux/main/examples/mimikatz_execution.yml
detectl -p elastic rules create-from-sigma mimikatz.yml --dry-run
```

Swap `elastic` for `qradar`, `crowdstrike`, `chronicle`, etc. to see the same rule converted differently per platform. Drop `--dry-run` and it actually creates the rule -- that part does need real credentials in `~/.detectl/config.yml` first (see Configure above):

```bash
detectl -p elastic rules create-from-sigma mimikatz.yml
```

A few platforms need one extra piece of platform-specific context a generic Sigma rule doesn't carry (CrowdStrike's IOA rule group, Sumo Logic's Monitors folder) -- pass it with repeatable `--raw KEY=VALUE`:

```bash
detectl -p sumologic rules create-from-sigma mimikatz.yml --raw parent_id=folder123
```

This isn't just a documented pairing: a separate `integration` job in this repo's CI checks out sigmux fresh, spins up a real Elasticsearch, and runs a full Sigma rule → sigmux → live Elasticsearch → detectl round trip against it end to end (see `scripts/integration_test_elastic.py`) -- so the two projects staying compatible is something CI actually verifies, not just a README claim.

The lower-level pairing (convert with sigmux, then feed the raw query text into `detectl query` yourself) still works too, and is what `create-from-sigma` does internally for the rule-creation path. `sigmux convert` runs with no credentials either way; `detectl query` (like `rules create-from-sigma` without `--dry-run`) needs a real, configured platform to actually query:

```bash
sigmux convert mimikatz.yml -t elastic -o out/
detectl -p elastic query "$(cat out/mimikatz.elastic.json)"

sigmux convert mimikatz.yml -t crowdstrike -o out/
detectl -p crowdstrike query "$(cat out/mimikatz.crowdstrike.lql)"
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
- `detectl/adapters/{splunk,elastic,sentinel,crowdstrike,qradar,sumologic,chronicle}.py`
  -- one self-contained file per platform, each mapping the canonical
  interface onto that platform's real REST API.
- `detectl/config.py` -- per-platform config loading from YAML and/or
  environment variables.
- `detectl/cli.py` -- the click-based CLI wiring the above together,
  including the sigmux bridge (`rules create-from-sigma`) and the
  Terraform-plan-style `--dry-run` diff view.
- `scripts/integration_test_elastic.py` -- the live, network-touching
  Sigma → sigmux → Elasticsearch → detectl round trip that CI's
  `integration` job runs (see Testing below); `scripts/generate_coverage_badge.py`
  is the self-hosted badge renderer behind the coverage badge above.

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
- **QRadar's Custom Rules Engine has no API for authoring rule logic** --
  `/analytics/rules` only manages metadata (enable/disable, delete) for
  rules that already exist; new rule logic has to be built through the
  in-product Rule Wizard. `create_rule`/`update_rule` raise
  `UnsupportedOperationError`; use `enable_rule`/`disable_rule` instead.
- **QRadar Reference Sets have no native "kind"** -- same `detectl_kind:
  {kind}` tag convention as Elastic's `meta.detectl_kind`, stored in the
  set's `description` field.
- **Sumo Logic Monitors need a destination folder** (Monitors Library is a
  folder tree, there's no bare/folder-less monitor) -- `create_rule`
  requires `rule.raw["parent_id"]`, same convention as CrowdStrike's
  `rule.raw["rule_group_id"]` for Custom IOA rules. Updates need the
  monitor's current `version` for optimistic concurrency, so
  `update_rule`/`set_rule_enabled` do a read-modify-write.
- **Sumo Logic Cloud SIEM Match Lists have no "kind" field** (they have a
  required `targetColumn` describing the *value type* -- IP, domain, file
  hash, ... -- instead) -- same tag-in-description convention as QRadar.
  Removing items needs match-list-item IDs, not raw values, so
  `remove_list_items` reads the current items first to resolve them.
- **Chronicle reference lists cannot be deleted via the API at all**
  (confirmed directly in Google's own Terraform provider source, which
  just drops the resource from state rather than deleting it) --
  `delete_list` raises `UnsupportedOperationError` rather than silently
  no-op'ing.
- **Chronicle detections only exist scoped to the rule that generated
  them** -- `list_alerts` requires a `rule_id` filter, and `get_alert` IDs
  are encoded as `"{rule_id}:{detection_id}"`, same shape as CrowdStrike's
  `"{rule_group_id}:{instance_id}"`. Detection triage/status lives in
  Chronicle's separate SOAR/case-management module, not a simple status
  field here, so `set_alert_status` raises `UnsupportedOperationError`.
- **Chronicle auth is a pre-obtained OAuth2 bearer token, not a full
  service-account flow** -- signing a JWT with an RSA private key is real
  crypto, out of scope for a dependency-light client. Get one with
  `gcloud auth print-access-token` (or your own refresh cron) and set it
  as `access_token`.

## Testing

No `pytest` dependency -- the whole suite runs on the standard library's
`unittest`. Every adapter test injects a fake `requests.Session` stand-in
(see `tests/helpers.py`) that asserts on exact HTTP calls and returns
canned responses, so the suite never touches the network and needs no
credentials:

```bash
python -m unittest discover -v
```

That's the fast, always-run signal that actually gates merges. Layered on top of it, a separate `integration` job in CI (see `scripts/integration_test_elastic.py`) deliberately does touch the network: it checks out sigmux, spins up a real Elasticsearch service container, and runs a full Sigma rule → sigmux → live Elasticsearch → detectl pipeline end to end. It's `continue-on-error` and its own job so a live-service flake never reddens the unit-test signal above.

## License

MIT
