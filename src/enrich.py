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

# Privileged-group-membership events (4732 and the domain equivalents 4728/
# 4756) reference the added member only via MemberSid within a ~1-hour
# correlation window - they're rare by construction, so a small cap is safe
# without risking truncation before the row that matters.
GROUP_EVENT_ROW_LIMIT = 20


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


def _query_rows(
    predicate: str, start: datetime, end: datetime, activity_time: datetime, limit: int
) -> list[dict]:
    """Run a windowed SecurityEvent query, prioritizing rows closest to the
    incident's actual activity time rather than the earliest rows in the
    window. A chronological-ascending take silently drops everything past
    the row cap - on a noisy host, that cap is often exhausted by
    unrelated background activity (e.g. agent/service churn) well before
    the window reaches the incident itself, so the rows that matter most
    never come back at all."""
    kql = (
        "SecurityEvent\n"
        f"| where TimeGenerated between (datetime({_format_kql_datetime(start)}) .. datetime({_format_kql_datetime(end)}))\n"
        f"| where {predicate}\n"
        f"| extend ActivityDistanceSeconds = abs(datetime_diff('second', TimeGenerated, datetime({_format_kql_datetime(activity_time)})))\n"
        "| order by ActivityDistanceSeconds asc\n"
        f"| take {limit}\n"
        "| project-away ActivityDistanceSeconds\n"
        "| order by TimeGenerated asc"
    )
    result = run_query(kql)
    return rows_to_dicts(result["tables"][0])


def _resolve_entity_sid(name: str, rows: list[dict]) -> str | None:
    """Find this Account entity's own SID from its already-fetched
    telemetry, so a follow-up query can also match privileged-group-
    membership events. On 4732/4728/4756, the added member is populated as
    MemberSid only - MemberName is usually blank, and TargetUserName on
    those events is the *group* name, not the member. So the name-based
    predicate in _entity_filter can never match these events for the
    entity being added, no matter how the window or row cap are tuned;
    the only way to find them is to know the entity's SID and query on
    MemberSid directly. See docs/detections.md."""
    for row in rows:
        if row.get("TargetUserName") == name and row.get("TargetSid"):
            return row["TargetSid"]
    for row in rows:
        if row.get("SubjectUserName") == name and row.get("SubjectUserSid"):
            return row["SubjectUserSid"]
    return None


def _merge_rows(*row_lists: list[dict]) -> list[dict]:
    """Combine results from multiple queries into one chronological list,
    dropping exact duplicate events (the same row can legitimately come
    back from more than one query)."""
    merged: dict[tuple, dict] = {}
    for rows in row_lists:
        for row in rows:
            key = (row.get("EventRecordId"), row.get("Computer"), row.get("TimeGenerated"))
            merged[key] = row
    return sorted(merged.values(), key=lambda r: r.get("TimeGenerated") or "")


def enrich_entity(
    entity: dict, start: datetime, end: datetime, activity_time: datetime
) -> list[dict]:
    predicate = _entity_filter(entity)
    if predicate is None:
        return []

    rows = _query_rows(predicate, start, end, activity_time, ROW_LIMIT)

    if entity["kind"] == "Account":
        sid = _resolve_entity_sid(entity["properties"]["accountName"], rows)
        if sid is not None:
            group_rows = _query_rows(
                f'MemberSid == "{sid}"', start, end, activity_time, GROUP_EVENT_ROW_LIMIT
            )
            rows = _merge_rows(rows, group_rows)

    return strip_null_columns(rows)


def enrich_bundle(bundle: dict) -> dict:
    """Attach surrounding SecurityEvent telemetry to each entity in a
    collect.py bundle, windowed WINDOW_MINUTES before/after the incident's
    activity span."""
    props = bundle["incident"]["properties"]
    first = _parse_utc(props["firstActivityTimeUtc"])
    last = _parse_utc(props["lastActivityTimeUtc"])
    window_start = first - timedelta(minutes=WINDOW_MINUTES)
    window_end = last + timedelta(minutes=WINDOW_MINUTES)
    activity_time = first + (last - first) / 2

    enriched_entities = [
        {**entity, "telemetry": enrich_entity(entity, window_start, window_end, activity_time)}
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
