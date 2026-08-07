import json
import sys
import os
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv

from auth import get_log_analytics_token

load_dotenv()

WORKSPACE_ID = os.environ["LOG_ANALYTICS_WORKSPACE_ID"]
QUERY_URL = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"

WINDOW_MINUTES = 30
ROW_LIMIT = 100


def _parse_utc(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def _format_kql_datetime(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _entity_filter(entity: dict) -> str | None:
    """Build a KQL predicate matching SecurityEvent rows for this entity.
    Returns None for entity kinds this lab doesn't have a mapping for."""
    kind = entity["kind"]
    props = entity["properties"]

    if kind == "Account":
        # The Account column is always the actor performing an action, never
        # the target - e.g. on a 4720 (account created), Account is the
        # admin who created it, and the new account name is in
        # TargetUserName instead. Search all three so we catch the entity
        # whichever role it played.
        name = props["accountName"]
        return f'Account has "{name}" or TargetUserName has "{name}" or SubjectUserName has "{name}"'
    if kind == "Host":
        return f'Computer has "{props["hostName"]}"'
    return None


def run_query(kql: str) -> dict:
    token = get_log_analytics_token()
    response = requests.post(
        QUERY_URL,
        headers={"Authorization": f"Bearer {token}"},
        json={"query": kql},
    )
    response.raise_for_status()
    return response.json()


def rows_to_dicts(table: dict) -> list[dict]:
    columns = [c["name"] for c in table["columns"]]
    return [dict(zip(columns, row)) for row in table["rows"]]


def strip_null_columns(records: list[dict]) -> list[dict]:
    """Drop any column that's empty across every row. SecurityEvent has
    dozens of columns that are unused for most event types - keeping them
    just wastes tokens once this feeds an LLM."""
    if not records:
        return records
    keys_with_data = {
        key
        for record in records
        for key, value in record.items()
        if value not in (None, "")
    }
    return [{k: v for k, v in record.items() if k in keys_with_data} for record in records]


def enrich_entity(entity: dict, start: datetime, end: datetime) -> list[dict]:
    predicate = _entity_filter(entity)
    if predicate is None:
        return []

    kql = (
        "SecurityEvent\n"
        f"| where TimeGenerated between (datetime({_format_kql_datetime(start)}) .. datetime({_format_kql_datetime(end)}))\n"
        f"| where {predicate}\n"
        "| order by TimeGenerated asc\n"
        f"| take {ROW_LIMIT}"
    )
    result = run_query(kql)
    return strip_null_columns(rows_to_dicts(result["tables"][0]))


def enrich_bundle(bundle: dict) -> dict:
    """Attach surrounding SecurityEvent telemetry to each entity in a
    collect.py bundle, windowed WINDOW_MINUTES before/after the incident's
    activity span."""
    props = bundle["incident"]["properties"]
    window_start = _parse_utc(props["firstActivityTimeUtc"]) - timedelta(minutes=WINDOW_MINUTES)
    window_end = _parse_utc(props["lastActivityTimeUtc"]) + timedelta(minutes=WINDOW_MINUTES)

    enriched_entities = [
        {**entity, "telemetry": enrich_entity(entity, window_start, window_end)}
        for entity in bundle["entities"]
    ]

    return {
        **bundle,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
        "entities": enriched_entities,
    }


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/incident-13.json"
    with open(path, encoding="utf-8") as f:
        bundle = json.load(f)

    enriched = enrich_bundle(bundle)

    out_path = path.replace(".json", "-enriched.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2)

    print(f"Saved {out_path}")
    for entity in enriched["entities"]:
        name = entity["properties"].get("accountName") or entity["properties"].get("hostName")
        print(f"  {entity['kind']} {name}: {len(entity['telemetry'])} event(s)")
