import json
import sys
from pathlib import Path

import anthropic
from dotenv import load_dotenv

load_dotenv()

MODEL = "claude-sonnet-5"
SYSTEM_PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "triage_system.md"

TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "attack_narrative": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "time": {"type": "string"},
                    "step": {"type": "string"},
                },
                "required": ["time", "step"],
                "additionalProperties": False,
            },
        },
        "mitre_techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "technique_name": {"type": "string"},
                    "tactic": {"type": "string"},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                },
                "required": ["technique_id", "technique_name", "tactic", "evidence", "confidence"],
                "additionalProperties": False,
            },
        },
        "suggested_verdict": {
            "type": "string",
            "enum": ["TruePositive", "BenignPositive", "FalsePositive", "Undetermined"],
        },
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "verification_needed": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "summary",
        "attack_narrative",
        "mitre_techniques",
        "suggested_verdict",
        "recommended_actions",
        "verification_needed",
    ],
    "additionalProperties": False,
}


def build_user_message(bundle: dict) -> str:
    return (
        "Triage the following Microsoft Sentinel incident using only the "
        "evidence below.\n\n" + json.dumps(bundle, indent=2)
    )


def triage_bundle(bundle: dict) -> dict:
    client = anthropic.Anthropic()
    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=SYSTEM_PROMPT_PATH.read_text(encoding="utf-8"),
        messages=[{"role": "user", "content": build_user_message(bundle)}],
        output_config={"format": {"type": "json_schema", "schema": TRIAGE_SCHEMA}},
    )

    if response.stop_reason == "refusal":
        raise RuntimeError("Claude declined to triage this incident (safety refusal).")

    text = next(block.text for block in response.content if block.type == "text")
    return json.loads(text)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/incident-13-enriched.json"
    with open(path, encoding="utf-8") as f:
        bundle = json.load(f)

    result = triage_bundle(bundle)

    incident_number = bundle["incident"]["properties"]["incidentNumber"]
    out_path = f"samples/incident-{incident_number}-triage.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"Saved {out_path}\n")
    print(result["summary"])
    print("\nMITRE techniques:")
    for t in result["mitre_techniques"]:
        print(f"  {t['technique_id']} ({t['confidence']}): {t['technique_name']}")
    print("\nSuggested verdict:", result["suggested_verdict"])
    if result["verification_needed"]:
        print("\nNeeds human verification:")
        for item in result["verification_needed"]:
            print(f"  - {item}")
