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
@click.pass_context
@handle_errors
def rules_create(ctx: click.Context, file_path: Path):
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
    _print(_adapter(ctx).create_rule(rule))


@rules.command("update")
@click.argument("rule_id")
@click.option("--file", "-f", "file_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.pass_context
@handle_errors
def rules_update(ctx: click.Context, rule_id: str, file_path: Path):
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
    _print(_adapter(ctx).update_rule(rule_id, rule))


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
    including output straight from `sigmux convert --target elasticsearch`."""
    result = _adapter(ctx).run_query(query_text, limit=limit, start=start, end=end)
    click.echo(json.dumps({"columns": result.columns, "rows": result.rows}, indent=2, default=str))


if __name__ == "__main__":
    main()
