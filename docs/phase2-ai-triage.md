# Phase 2: AI-Augmented Incident Triage

Status: in progress. Detection and incident-generation prerequisites are complete
(four analytics rules live, incidents generating with mapped entities). This phase adds
an automated triage layer on top of the working SIEM.

## Goal

Pull Microsoft Sentinel incidents through the REST API, enrich each one with the raw
Windows event telemetry surrounding it, send that bundle to an LLM for structured triage,
and write the result back into the incident as a comment. The output is a plain-English
summary, a chronological attack narrative, MITRE ATT&CK technique mapping with cited
evidence, a suggested verdict, and recommended analyst actions.

## Architecture

```
Sentinel incident (REST API)
      |
   collect      pull incident + alerts + mapped entities
      |
   enrich       for each entity, query surrounding SecurityEvent rows
      |
   triage       send bundle to LLM, receive structured JSON
      |
   write back   render to markdown, PUT as incident comment
      |
   evaluate     score model output against known ground truth
```

The collector and enrichment layer are built and validated first, working against saved
JSON samples, before any model call. Developing against saved samples avoids hitting the
Azure API and paying for tokens on every iteration.

## Why this is not just an API wrapper

Two design choices carry the project past "call an LLM on an alert."

**Enrichment.** An incident on its own gives a model almost nothing: a title, a severity,
a couple of entities. The enrichment layer pulls the actual event telemetry around each
mapped entity, the failed logons before a lockout, the process tree around a suspicious
command, so the model reasons over evidence instead of a headline.

**Ground-truth evaluation.** Because the attacks in this lab were generated deliberately,
the correct MITRE technique for every incident is known in advance. That makes it possible
to measure the model's technique mapping with precision and recall, and its verdict against
a labeled answer, rather than eyeballing whether the output "looks right." Most LLM-plus-SIEM
projects skip this. The eval turns the project from a demo into a measured result.

Ground truth for the simulated scenarios:

| Scenario | Technique |
|---|---|
| SMB failed-logon brute force | T1110 |
| `net user /add` | T1136.001 |
| `net localgroup Administrators /add` | T1098 |
| Encoded / hidden PowerShell | T1059.001, T1027 |
| Scheduled task persistence | T1053.005 |
| Remote exec over SMB (psexec) | T1569.002 |
| WinRM remote shell (evil-winrm) | T1021.006 |

## Guardrails

The triage prompt requires the model to cite the specific event supporting each MITRE
mapping and to list what a human should verify that the data does not answer. This is the
control against confident hallucinated technique mappings, which is the failure mode a
reviewer will look for first. The pipeline writes an AI comment labeled as automated and
unverified. It does not auto-close incidents. Auto-classification without a human in the
loop is the wrong design for this kind of tool.

## Components (planned)

- `collect.py` - pull an incident with its alerts and entities into a JSON bundle
- `enrich.py` - attach surrounding SecurityEvent telemetry per entity
- `triage.py` - structured LLM call, JSON output against a fixed schema
- `writeback.py` - render triage to markdown, PUT as an incident comment
- `report.py` - roll up N triaged incidents into an executive summary
- `evals/` - ground-truth labels and a scoring script for technique precision/recall
