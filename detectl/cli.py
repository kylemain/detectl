"""Command-line interface for detectl."""
from __future__ import annotations

import dataclasses
import functools
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

from .adapters import REGISTRY, get_adapter
from .adapters.base import SIEMAdapter
from .exceptions import DetectlError
from .models import ListObject, Rule


def _to_dict(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    return obj


def _print(obj: Any) -> None:
    if isinstance(obj, list):
        payload = [_to_dict(o) for o in obj]
    else:
        payload = _to_dict(obj)
    click.echo(json.dumps(payload, indent=2, default=str))


def _load_json_file(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def handle_errors(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except DetectlError as exc:
            click.secho(f"error: {exc}", fg="red", err=True)
            sys.exit(1)

    return wrapper


# sigmux's target names match detectl's platform names 1:1 (deliberately --
# see sigmux's README). Kept as an explicit mapping rather than assumed
# identity so the two projects can drift without silently breaking this.
_SIGMUX_TARGET_FOR: Dict[str, str] = {name: name for name in REGISTRY}


def _load_sigmux():
    try:
        from sigmux.backends import get_backend
        from sigmux.rule import SigmaRule
    except ImportError as exc:
        raise click.ClickException(
            "rules create-from-sigma needs sigmux installed: pip install 'detectl[sigma]' "
            "(sigmux isn't on PyPI yet -- that extra installs it straight from "
            "https://github.com/kylemain/sigmux)"
        ) from exc
    return SigmaRule, get_backend


def _load_rich():
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text
    except ImportError as exc:
        raise click.ClickException(
            "--dry-run needs rich installed: pip install 'detectl[dryrun]'"
        ) from exc
    return Console, Panel, Text


def _append_field(body, sign: str, key: str, value: Any, style: str) -> None:
    if isinstance(value, str) and "\n" in value:
        body.append(f"  {sign} {key}:\n", style=style)
        for line in value.splitlines():
            body.append(f"        {line}\n", style=style)
    else:
        body.append(f"  {sign} {key}: {value!r}\n", style=style)


def _print_plan(action: str, before: Optional[Dict[str, Any]], after: Dict[str, Any]) -> None:
    """Terraform-plan-style diff: unchanged fields dim, changed fields shown
    as a red '-' old value followed by a green '+' new value, new-only
    fields (create) shown green-only. Nothing is applied -- this is purely
    a preview of what a real run would do."""
    Console, Panel, Text = _load_rich()
    console = Console()
    body = Text()
    keys = sorted(set(after) | set(before or {}))
    unchanged = 0
    for key in keys:
        old_val, new_val = (before or {}).get(key), after.get(key)
        if before is not None and old_val == new_val:
            unchanged += 1
            continue
        if before is None:
            _append_field(body, "+", key, new_val, "green")
        else:
            _append_field(body, "-", key, old_val, "red")
            _append_field(body, "+", key, new_val, "green")
    if unchanged:
        body.append(f"  ({unchanged} unchanged field(s) not shown)\n", style="dim")
    if not body.plain.strip():
        body.append("  (no changes)\n", style="dim")

    console.print(Panel(body, title=f"PLAN: {action}", title_align="left", border_style="yellow"))
    console.print("[dim]Dry run -- nothing was changed. Re-run without --dry-run to apply.[/dim]")


@click.group()
@click.option("--platform", "-p", type=click.Choice(sorted(REGISTRY)), help="Target SIEM platform.")
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to config file (default: ~/.detectl/config.yml).",
)
@click.pass_context
def main(ctx: click.Context, platform: Optional[str], config_path: Optional[Path]):
    """detectl -- a CLI for managing detection rules, tuning lists, alerts,
    and ad-hoc queries across multiple SIEM/EDR platforms through one
    consistent interface."""
    ctx.ensure_object(dict)
    ctx.obj["platform"] = platform
    ctx.obj["config_path"] = config_path


def _adapter(ctx: click.Context) -> SIEMAdapter:
    platform = ctx.obj.get("platform")
    if not platform:
        raise click.UsageError("--platform/-p is required (e.g. `detectl -p splunk rules list`)")
    return get_adapter(platform, ctx.obj.get("config_path"))


@main.command()
def targets():
    """List supported SIEM/EDR platforms."""
    for name in sorted(REGISTRY):
        click.echo(name)


@main.command("test-connection")
@click.pass_context
@handle_errors
def test_connection(ctx: click.Context):
    """Verify configured credentials/connectivity for --platform."""
    adapter = _adapter(ctx)
    adapter.test_connection()
    click.secho(f"OK: connected to {adapter.name}", fg="green")


# ---------------------------------------------------------------- rules --
@main.group()
def rules():
    """Manage detection rules."""


@rules.command("list")
@click.pass_context
@handle_errors
def rules_list(ctx: click.Context):
    _print(_adapter(ctx).list_rules())


@rules.command("get")
@click.argument("rule_id")
@click.pass_context
@handle_errors
def rules_get(ctx: click.Context, rule_id: str):
    _print(_adapter(ctx).get_rule(rule_id))


@rules.command("create")
@click.option("--file", "-f", "file_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--dry-run", is_flag=True, help="Show what would be created without creating it.")
@click.pass_context
@handle_errors
def rules_create(ctx: click.Context, file_path: Path, dry_run: bool):
    data = _load_json_file(file_path)
    rule = Rule(
        id=data.get("id"),
        name=data["name"],
        query=data.get("query", ""),
        description=data.get("description", ""),
        severity=data.get("severity", "medium"),
        enabled=data.get("enabled", True),
        tags=data.get("tags", []),
        raw=data.get("raw", {}),
    )
    if dry_run:
        _print_plan("create", None, dataclasses.asdict(rule))
        return
    _print(_adapter(ctx).create_rule(rule))


@rules.command("update")
@click.argument("rule_id")
@click.option("--file", "-f", "file_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--dry-run", is_flag=True, help="Show the diff against the current rule without applying it.")
@click.pass_context
@handle_errors
def rules_update(ctx: click.Context, rule_id: str, file_path: Path, dry_run: bool):
    data = _load_json_file(file_path)
    rule = Rule(
        id=rule_id,
        name=data["name"],
        query=data.get("query", ""),
        description=data.get("description", ""),
        severity=data.get("severity", "medium"),
        enabled=data.get("enabled", True),
        tags=data.get("tags", []),
        raw=data.get("raw", {}),
    )
    if dry_run:
        current = _adapter(ctx).get_rule(rule_id)
        _print_plan("update", dataclasses.asdict(current), dataclasses.asdict(rule))
        return
    _print(_adapter(ctx).update_rule(rule_id, rule))


@rules.command("create-from-sigma")
@click.argument("sigma_file", type=click.Path(exists=True, path_type=Path))
@click.option("--severity", default=None, help="Override severity (defaults to the Sigma rule's `level`).")
@click.option(
    "--raw",
    "raw_fields",
    multiple=True,
    metavar="KEY=VALUE",
    help="Extra raw field some platforms require (e.g. --raw parent_id=folder1 for Sumo Logic Monitors, "
    "--raw rule_group_id=xyz for CrowdStrike Custom IOA rules). Repeatable.",
)
@click.option("--dry-run", is_flag=True, help="Show what would be created, including the converted query, without creating it.")
@click.pass_context
@handle_errors
def rules_create_from_sigma(ctx: click.Context, sigma_file: Path, severity: Optional[str], raw_fields: List[str], dry_run: bool):
    """Convert a Sigma rule with sigmux and create it as a detection rule on
    --platform in one step -- the two-command "sigmux convert | detectl
    rules create" pairing collapsed into one, so the conversion target is
    never a manual step you can get out of sync with --platform."""
    platform = ctx.obj.get("platform")
    if not platform:
        raise click.UsageError("--platform/-p is required (e.g. `detectl -p elastic rules create-from-sigma rule.yml`)")

    SigmaRule, get_backend = _load_sigmux()
    sigma_target = _SIGMUX_TARGET_FOR.get(platform, platform)
    try:
        backend = get_backend(sigma_target)
    except ValueError as exc:
        raise click.ClickException(f"sigmux has no '{sigma_target}' target for platform '{platform}': {exc}")

    sigma_rule = SigmaRule.from_yaml(sigma_file.read_text(encoding="utf-8"))
    query = backend.render(sigma_rule)

    raw: Dict[str, Any] = {}
    for item in raw_fields:
        key, sep, value = item.partition("=")
        if not sep:
            raise click.UsageError(f"--raw expects KEY=VALUE, got: {item!r}")
        raw[key] = value

    rule = Rule(
        id=None,
        name=sigma_rule.title,
        query=query,
        description=sigma_rule.description or "",
        severity=severity or sigma_rule.level or "medium",
        enabled=True,
        tags=sigma_rule.tags,
        raw=raw,
    )

    if dry_run:
        plan = dataclasses.asdict(rule)
        plan["_sigmux_target"] = sigma_target
        _print_plan("create (via sigmux)", None, plan)
        return
    _print(_adapter(ctx).create_rule(rule))


@rules.command("delete")
@click.argument("rule_id")
@click.pass_context
@handle_errors
def rules_delete(ctx: click.Context, rule_id: str):
    _adapter(ctx).delete_rule(rule_id)
    click.secho(f"deleted rule {rule_id}", fg="green")


@rules.command("enable")
@click.argument("rule_id")
@click.pass_context
@handle_errors
def rules_enable(ctx: click.Context, rule_id: str):
    _print(_adapter(ctx).enable_rule(rule_id))


@rules.command("disable")
@click.argument("rule_id")
@click.pass_context
@handle_errors
def rules_disable(ctx: click.Context, rule_id: str):
    _print(_adapter(ctx).disable_rule(rule_id))


# ---------------------------------------------------------------- lists --
@main.group()
def lists():
    """Manage watchlists, exclusion/allow/block lists, suppression lists,
    and KV stores."""


@lists.command("list")
@click.option("--kind", default=None, help="Filter by list kind (e.g. watchlist, exclusion, allowlist).")
@click.pass_context
@handle_errors
def lists_list(ctx: click.Context, kind: Optional[str]):
    _print(_adapter(ctx).list_lists(kind=kind))


@lists.command("get")
@click.argument("list_id")
@click.pass_context
@handle_errors
def lists_get(ctx: click.Context, list_id: str):
    _print(_adapter(ctx).get_list(list_id))


@lists.command("create")
@click.option("--file", "-f", "file_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.pass_context
@handle_errors
def lists_create(ctx: click.Context, file_path: Path):
    data = _load_json_file(file_path)
    list_obj = ListObject(
        id=data.get("id"),
        name=data["name"],
        kind=data.get("kind", "watchlist"),
        description=data.get("description", ""),
        items=data.get("items", []),
        raw=data.get("raw", {}),
    )
    _print(_adapter(ctx).create_list(list_obj))


@lists.command("update")
@click.argument("list_id")
@click.option("--file", "-f", "file_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.pass_context
@handle_errors
def lists_update(ctx: click.Context, list_id: str, file_path: Path):
    data = _load_json_file(file_path)
    list_obj = ListObject(
        id=list_id,
        name=data["name"],
        kind=data.get("kind", "watchlist"),
        description=data.get("description", ""),
        items=data.get("items", []),
        raw=data.get("raw", {}),
    )
    _print(_adapter(ctx).update_list(list_id, list_obj))


@lists.command("delete")
@click.argument("list_id")
@click.pass_context
@handle_errors
def lists_delete(ctx: click.Context, list_id: str):
    _adapter(ctx).delete_list(list_id)
    click.secho(f"deleted list {list_id}", fg="green")


@lists.command("add-items")
@click.argument("list_id")
@click.option("--item", "-i", "items", multiple=True, required=True, help="Repeatable.")
@click.pass_context
@handle_errors
def lists_add_items(ctx: click.Context, list_id: str, items: List[str]):
    _print(_adapter(ctx).add_list_items(list_id, list(items)))


@lists.command("remove-items")
@click.argument("list_id")
@click.option("--item", "-i", "items", multiple=True, required=True, help="Repeatable.")
@click.pass_context
@handle_errors
def lists_remove_items(ctx: click.Context, list_id: str, items: List[str]):
    _print(_adapter(ctx).remove_list_items(list_id, list(items)))


# --------------------------------------------------------------- alerts --
@main.group()
def alerts():
    """Manage alerts/incidents."""


@alerts.command("list")
@click.option("--limit", default=100)
@click.pass_context
@handle_errors
def alerts_list(ctx: click.Context, limit: int):
    _print(_adapter(ctx).list_alerts(limit=limit))


@alerts.command("get")
@click.argument("alert_id")
@click.pass_context
@handle_errors
def alerts_get(ctx: click.Context, alert_id: str):
    _print(_adapter(ctx).get_alert(alert_id))


@alerts.command("set-status")
@click.argument("alert_id")
@click.argument("status")
@click.pass_context
@handle_errors
def alerts_set_status(ctx: click.Context, alert_id: str, status: str):
    _print(_adapter(ctx).set_alert_status(alert_id, status))


# --------------------------------------------------------------- events --
@main.command()
@click.argument("query_text", metavar="QUERY")
@click.option("--limit", default=100)
@click.option("--start", default=None)
@click.option("--end", default=None)
@click.pass_context
@handle_errors
def query(ctx: click.Context, query_text: str, limit: int, start: Optional[str], end: Optional[str]):
    """Run a raw, platform-native query (SPL / ES Query DSL / KQL) and print
    the results. Elasticsearch's DSL can be passed as a JSON string --
    including output straight from `sigmux convert --target elastic`."""
    result = _adapter(ctx).run_query(query_text, limit=limit, start=start, end=end)
    click.echo(json.dumps({"columns": result.columns, "rows": result.rows}, indent=2, default=str))


if __name__ == "__main__":
    main()
