# Triage Eval Results

Scores `triage.py`'s `mitre_techniques` output against each analytics rule's *intended* MITRE technique tags (`evals/ground_truth.json`), with every prediction independently verified against the incident's enriched telemetry - a technique ID matching ground truth only counts as a true positive if its cited evidence is real. See `evals/score.py` module docstring for the full scoring rules.

**The headline below is the strict, automated-only result** - `record_id` and `eventid_timestamp` grounding only. A third tier (`eventid_crossref`) exists in `evals/score.py` and is documented later in this report, but it is not applied to the headline. It was added after the first run of this eval scored 92% recall, and folding it into the reported number at that point would invite a fair "did you tune the eval to pass" question - even though the reasoning behind it holds up under review. Reporting the stricter number is the more credible choice.

## Headline (strict, automated-only; micro-averaged across all 7 incidents)

- **Precision: 100%** (11 grounded TP / 11 predictions counted)
- **Recall: 92%** (11 grounded TP / 12 ground-truth labels)
- Macro-averaged precision/recall: 100% / 93%

## The one recall miss

Incident 5 (Suspicious PowerShell Command Line Execution), technique `T1027`, model confidence `low`, scored `tp_label_ungrounded`.

**Evidence cited by the model:** "EventID 4688 CommandLine field uses '-encodedCommand' with a Base64-encoded payload, which is the specific field/indicator the analytic rule matched on (alert AdditionalData.MitreTechniques includes T1027)"

**Automated scorer's verdict:** "evidence cites neither a checkable EventRecordId nor an 'EventID <n> ... <timestamp>' claim - nothing to verify against the bundle, treated conservatively as not grounded"

**Manual review:** this citation is real, not fabricated. The same EventID 4688 command line was independently verified (via `EventRecordId`) for `T1059.001` in this same incident's output - `T1027` is describing the identical event, just without repeating a timestamp or record ID of its own. It is a genuine finding, thinly cited. The strict scorer has no way to distinguish "thinly cited but true" from "fabricated" without either a corroboration rule (which is exactly what `eventid_crossref` adds, see below) or a human reading it - and a human did read it, here.

This is the point of reporting the stricter number: the eval is rigorous enough to flag a real, correct technique when its citation doesn't meet the bar, rather than passing everything that happens to be true. A softer eval that never produces a miss like this one isn't more accurate, it's just not being tested.

---

## The eval discriminates: incident 13, before and after the enrich.py fix

| | Pre-fix (buggy telemetry) | Post-fix (corrected telemetry) |
|---|---|---|
| T1098 confidence (model-reported) | `low` | `high` |
| T1098 grounding method | `unverifiable` | `record_id` |
| T1098 eval category | **`tp_label_ungrounded`** | **`tp`** |
| Incident recall | 50% | 100% |
| Incident precision | 100% | 100% |

**Pre-fix T1098 evidence cited by the model:** "evidence cites neither a checkable EventRecordId nor an 'EventID <n> ... <timestamp>' claim - nothing to verify against the bundle, treated conservatively as not grounded"

**Post-fix T1098 evidence cited by the model:** "EventRecordId(s) ['1199', '67871'] verified present in enriched bundle"

The scorer's `tp_label_ungrounded` category exists specifically for this case: the predicted technique ID matches ground truth, but the cited evidence doesn't check out against real telemetry (here, because none was extractable to check at all - the model was citing the alert's own rule description, not an observed event). That's scored as a miss for recall, not a free pass because the label happened to match. The post-fix run cites a real `EventRecordId` that the scorer verified exists in the enriched bundle, and is scored as a genuine true positive.

This is the key finding of this eval, not the 92% or the 100%: the same rubric, applied to the same incident before and after a real data-pipeline fix, correctly separates a grounded finding from an ungrounded one. That's what makes the batch score above credible - it comes from a scorer that has been shown to fail the model when the model's evidence doesn't hold up.

---

## Documented refinement: `eventid_crossref` (not part of the headline)

Applying the `eventid_crossref` tier (`classify_incident(..., enable_crossref=True)`) resolves incident 5's `T1027` from `tp_label_ungrounded` to `tp`, since its bare EventID citation matches one already independently verified for `T1059.001` in the same incident:

- With `eventid_crossref` applied: precision 100%, recall 100% (micro)
- **This is a documented refinement, not the reported result.** It stays in `evals/score.py`, off by default, because adding a grounding rule after seeing that it would resolve the one miss - and then reporting the improved number - would make the eval's rigor harder to trust, even though the rule is sound and would apply to any future incident, not just this one. The strict, automated-only result above is the headline.

---

## Per-incident breakdown (strict scoring)

### Incident 8 - Multiple Failed Logons from Single Source (Brute Force)

Ground truth: `T1110`  
Precision: 100%  Recall: 100%

| Technique | Confidence | Category | Grounding method | Detail |
|---|---|---|---|---|
| T1110 | high | `tp` | eventid_timestamp | EventID 4625 at 2026-08-04T21:31:19.41Z verified within 2s of a real bundle row (2026-08-04T21:31:19 |
| T1110.001 | medium | `refinement` | unverifiable | evidence cites neither a checkable EventRecordId nor an 'EventID <n> ... <timestamp>' claim - nothin |
| T1078 | low | `additional_grounded` | eventid_timestamp | EventID 4624 at 21:31:19.34Z verified within 2s of a real bundle row (2026-08-04T21:31:19.336933+00: |

### Incident 2 - Account Added to Privileged Group

Ground truth: `T1098`  
Precision: 100%  Recall: 100%

| Technique | Confidence | Category | Grounding method | Detail |
|---|---|---|---|---|
| T1098 | high | `tp` | eventid_timestamp | EventID 4732 at 2026-08-04T18:55:30.53Z verified within 2s of a real bundle row (2026-08-04T18:55:30 |
| T1136.001 | high | `additional_grounded` | eventid_timestamp | EventID 4720 at 2026-08-04T21:43:54.238Z verified within 2s of a real bundle row (2026-08-04T21:43:5 |
| T1110 | medium | `additional_grounded` | eventid_timestamp | EventID 4625 at 2026-08-04T19:13:14Z verified within 2s of a real bundle row (2026-08-04T19:13:14.95 |
| T1059.001 | medium | `additional_grounded` | eventid_timestamp | EventID 4688 at 2026-08-04T18:55:30Z verified within 2s of a real bundle row (2026-08-04T18:55:30.49 |

### Incident 13 - New Account Created and Rapidly Elevated

Ground truth: `T1136.001, T1098`  
Precision: 100%  Recall: 100%

| Technique | Confidence | Category | Grounding method | Detail |
|---|---|---|---|---|
| T1136.001 | high | `tp` | record_id | EventRecordId(s) ['1197', '67865'] verified present in enriched bundle |
| T1098 | high | `tp` | record_id | EventRecordId(s) ['1199', '67871'] verified present in enriched bundle |
| T1059.001 | high | `additional_grounded` | record_id | EventRecordId(s) ['67858'] verified present in enriched bundle |
| T1027 | medium | `additional_grounded` | record_id | EventRecordId(s) ['1201', '67876'] verified present in enriched bundle |
| T1110 | low | `additional_grounded` | record_id | EventRecordId(s) ['67915', '67916', '67917', '67918', '67919', '67920'] verified present in enriched |

### Incident 16 - New Account Created and Rapidly Elevated

Ground truth: `T1136.001, T1098`  
Precision: 100%  Recall: 100%

| Technique | Confidence | Category | Grounding method | Detail |
|---|---|---|---|---|
| T1136.001 | high | `tp` | eventid_timestamp | EventID 4720 at 2026-08-04T21:43:54Z verified within 2s of a real bundle row (2026-08-04T21:43:54.23 |
| T1098 | high | `tp` | eventid_timestamp | EventID 4732 at 2026-08-04T21:44:11Z verified within 2s of a real bundle row (2026-08-04T21:44:11.41 |
| T1059.001 | high | `additional_grounded` | eventid_timestamp | EventID 4688 at 21:43:29Z verified within 2s of a real bundle row (2026-08-04T21:43:29.534610+00:00) |
| T1027 | medium | `additional_grounded` | eventid_timestamp | EventID 4104 at 2026-08-04T21:45:06Z verified within 2s of a real bundle row (2026-08-04T21:45:06.15 |
| T1110 | low | `additional_grounded` | eventid_timestamp | EventID 4625 at 21:46:35Z verified within 2s of a real bundle row (2026-08-04T21:46:35.789964+00:00) |

### Incident 3 - Suspicious PowerShell Command Line Execution

Ground truth: `T1059.001, T1027`  
Precision: 100%  Recall: 100%

| Technique | Confidence | Category | Grounding method | Detail |
|---|---|---|---|---|
| T1059.001 | low | `tp` | record_id | EventRecordId(s) ['66655', '66658'] verified present in enriched bundle |
| T1027 | low | `tp` | record_id | EventRecordId(s) ['66655', '66658'] verified present in enriched bundle |
| T1059 | low | `redundant` | record_id | EventRecordId(s) ['66655', '66658'] verified present in enriched bundle |

### Incident 4 - Suspicious PowerShell Command Line Execution

Ground truth: `T1059.001, T1027`  
Precision: 100%  Recall: 100%

| Technique | Confidence | Category | Grounding method | Detail |
|---|---|---|---|---|
| T1059.001 | low | `tp` | record_id | EventRecordId(s) ['67260', '67263'] verified present in enriched bundle |
| T1027 | low | `tp` | record_id | EventRecordId(s) ['1169', '1174', '67260', '67263'] verified present in enriched bundle |

### Incident 5 - Suspicious PowerShell Command Line Execution

Ground truth: `T1059.001, T1027`  
Precision: 100%  Recall: 50%

| Technique | Confidence | Category | Grounding method | Detail |
|---|---|---|---|---|
| T1059.001 | high | `tp` | eventid_timestamp | EventID 4688 at 2026-08-04T21:06:06.4689912Z verified within 2s of a real bundle row (2026-08-04T21: |
| T1027 | low | `tp_label_ungrounded` | unverifiable | evidence cites neither a checkable EventRecordId nor an 'EventID <n> ... <timestamp>' claim - nothin |

*T1027 above is the one strict-scoring miss - see "The one recall miss" and "Documented refinement" sections above for the full detail.*

## Confidence calibration (strict scoring)

Does the model's self-reported confidence track whether a finding actually holds up? Rank: low=0, medium=1, high=2 - higher average rank should track more trustworthy categories.

| Category | n | low | medium | high | avg rank |
|---|---|---|---|---|---|
| `tp` | 11 | 4 | 0 | 7 | 1.27 |
| `tp_label_ungrounded` | 1 | 1 | 0 | 0 | 0.00 |
| `additional_grounded` | 10 | 3 | 4 | 3 | 1.00 |
| `refinement` | 1 | 0 | 1 | 0 | 1.00 |
| `redundant` | 1 | 1 | 0 | 0 | 0.00 |

The single `tp_label_ungrounded` entry (incident 5's `T1027`) was self-rated `low` confidence by the model - its own signal lines up with the scorer's, for whatever that's worth on a sample of one.

## Design notes / known limitations

- Grounding verification is automated in two tiers used for the headline: `record_id` (exact EventRecordId match) and `eventid_timestamp` (EventID + timestamp within a 2s tolerance). A third tier, `eventid_crossref`, exists and is documented above but is off by default and excluded from the reported score.
- `refinement`/`redundant` classification is based on MITRE ID prefix relationship to an already-grounded item in the same incident, not on proving the two evidence citations share the same underlying event - in the cases in this batch they did (manually spot-checked), but the automated check doesn't require it.
- The pre-fix incident-13 fixture (`evals/fixtures/incident-13-pre-fix-triage.json`) is scored against the *current* (fixed) enriched bundle, not the actual pre-fix bundle it was originally run against (which was overwritten during re-enrichment). This is safe here because the only bundle content the pre-fix evidence actually relies on - the 4720 creation event - is unchanged by the fix; the T1098 evidence is scored as `unverifiable` purely from its own text (it cites no checkable claim), independent of which bundle is loaded.
