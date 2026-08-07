import json
import os
import sys
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

from auth import get_management_token

load_dotenv()

API_VERSION = "2025-09-01"

SUBSCRIPTION_ID = os.environ["AZURE_SUBSCRIPTION_ID"]
RESOURCE_GROUP = os.environ["AZURE_RESOURCE_GROUP"]
WORKSPACE_NAME = os.environ["SENTINEL_WORKSPACE_NAME"]

INCIDENTS_URL = (
    f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
    f"/resourceGroups/{RESOURCE_GROUP}"
    f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
    f"/providers/Microsoft.SecurityInsights/incidents"
)


def list_incidents(token: str) -> list[dict]:
    """Return every incident in the workspace, following nextLink pages."""
    incidents = []
    url = f"{INCIDENTS_URL}?api-version={API_VERSION}"
    while url:
        response = requests.get(url, headers={"Authorization": f"Bearer {token}"})
        response.raise_for_status()
        body = response.json()
        incidents.extend(body["value"])
        url = body.get("nextLink")
    return incidents


def find_incident_by_number(token: str, incident_number: int) -> dict:
    """The portal shows incidents by a human incidentNumber (e.g. #13), but the
    REST API addresses them by an internal GUID (the `name` field). Resolve
    one to the other by scanning the list."""
    for incident in list_incidents(token):
        if incident["properties"]["incidentNumber"] == incident_number:
            return incident
    raise ValueError(f"No incident with incidentNumber={incident_number}")


def get_incident_alerts(token: str, incident_name: str) -> list[dict]:
    url = f"{INCIDENTS_URL}/{incident_name}/alerts?api-version={API_VERSION}"
    response = requests.post(url, headers={"Authorization": f"Bearer {token}"})
    response.raise_for_status()
    return response.json()["value"]


def get_incident_entities(token: str, incident_name: str) -> list[dict]:
    url = f"{INCIDENTS_URL}/{incident_name}/entities?api-version={API_VERSION}"
    response = requests.post(url, headers={"Authorization": f"Bearer {token}"})
    response.raise_for_status()
    return response.json()["entities"]


def collect_incident(incident_number: int) -> dict:
    """Build the full JSON bundle for one incident: the incident itself, its
    alerts, and its entities. This is the unit enrich.py and triage.py will
    operate on next."""
    token = get_management_token()
    incident = find_incident_by_number(token, incident_number)
    incident_name = incident["name"]

    return {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "incident": incident,
        "alerts": get_incident_alerts(token, incident_name),
        "entities": get_incident_entities(token, incident_name),
    }


def save_bundle(bundle: dict) -> str:
    incident_number = bundle["incident"]["properties"]["incidentNumber"]
    path = f"samples/incident-{incident_number}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    return path


if __name__ == "__main__":
    if len(sys.argv) < 2:
        token = get_management_token()
        incidents = list_incidents(token)
        print(f"{len(incidents)} incident(s) in workspace:")
        for incident in incidents:
            props = incident["properties"]
            print(f"  #{props['incidentNumber']:<4} {props['title']:<50} {props['status']}")
        print("\nRun `python src/collect.py <incidentNumber>` to collect one.")
    else:
        bundle = collect_incident(int(sys.argv[1]))
        path = save_bundle(bundle)
        print(f"Saved {path}")
        print(f"  alerts:   {len(bundle['alerts'])}")
        print(f"  entities: {len(bundle['entities'])}")
