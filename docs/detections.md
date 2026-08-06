# Detection Engineering

Four scheduled analytics rules run in Microsoft Sentinel against the `SecurityEvent`
table. These are production-shaped detections, not the exploratory `project` dumps
used for pipeline validation. Each rule has explicit thresholds where a raw dump would
flood the queue, mapped entities so incidents are pivotable, a MITRE technique, and a
documented false-positive profile.

The raw `.kql` for each rule lives in [`/detections`](../detections). Screenshots of
each rule's configuration and a triggered incident are in
[`screenshots/`](screenshots).

## MITRE ATT&CK coverage

| Rule | Technique | Tactic |
|---|---|---|
| Multiple Failed Logons from Single Source | T1110 Brute Force | Credential Access |
| Account Added to Privileged Group | T1098 Account Manipulation | Persistence, Privilege Escalation |
| Suspicious PowerShell Command Line Execution | T1059.001 PowerShell, T1027 Obfuscated Files or Information | Execution, Defense Evasion |
| New Account Created and Rapidly Elevated | T1136.001 Create Account: Local Account, T1098 Account Manipulation | Persistence, Privilege Escalation |

---

## Rule 1: Multiple Failed Logons from Single Source (Brute Force)

**Technique:** T1110 (Brute Force) | **Severity:** Medium | **Schedule:** every 5 min, 1h lookback

Query: [`01-brute-force-failed-logons.kql`](../detections/01-brute-force-failed-logons.kql)

The rule aggregates 4625 events by source IP and host, then thresholds at 5 or more
failures in the window. The loopback and null addresses are excluded because service
and local failures show up there and are not brute force.

Two implementation details matter. First, after the `summarize` the original
`TimeGenerated` column no longer exists, so the query restores it with
`extend TimeGenerated = EndTime`. Without a timestamp column the rule fails to build an
alert. Second, the rule does not filter on `LogonType`. Network brute force comes in as
type 3 and RDP brute force as type 10, and keeping the rule type-agnostic lets one rule
catch both.

**Entity mapping:** IP (Address = `IpAddress`), Host (HostName = `Computer`)

**Custom details:** `FailedCount`, `TargetedAccounts`

**False positive sources:** a user fat-fingering a password a few times, a service
account with a stale cached credential hammering the DC after a password rotation, a
vulnerability scanner. Suppression: raise the threshold, or exclude known scanner and
service-account source IPs with a watchlist rather than editing the rule.

---

## Rule 2: Account Added to Privileged Group

**Technique:** T1098 (Account Manipulation) | **Severity:** High | **Schedule:** every 5 min, 1h lookback

Query: [`02-privileged-group-add.kql`](../detections/02-privileged-group-add.kql)

Fires on 4732 when the target group is one of the four privileged groups. The rule maps
the **actor** who performed the addition, not the account that was added. On 4732 the
added member is populated as `MemberSid` and the `MemberName` field is usually `-`, so
the added member cannot be mapped as a named Account entity. `TargetUserName` on a 4732
is the group name, not a user, which is a common misread of this event.

**Entity mapping:** Account (Name = `ActorUser`, NTDomain = `ActorDomain`), Host (HostName = `Computer`)

**Custom details:** `AddedMemberSid`, `GroupName`

**False positive sources:** legitimate administration. Adding a new hire to a privileged
group is a real business action that looks identical to the attack. This is why the rule
is High severity but not auto-actioned: it needs a human to confirm the change was
authorized. Suppression in production would come from correlating against a change
ticket, not from tuning the query.

---

## Rule 3: Suspicious PowerShell Command Line Execution

**Technique:** T1059.001 (PowerShell), T1027 (Obfuscated Files) | **Severity:** Medium | **Schedule:** every 5 min, 1h lookback

Query: [`03-suspicious-powershell-cmdline.kql`](../detections/03-suspicious-powershell-cmdline.kql)

Matches 4688 process creation events whose command line contains encoding, hidden-window,
profile-bypass, download, or execution-policy-bypass indicators.

This rule is deliberately built on the 4688 `CommandLine` column rather than on 4104
script block content. On this ingestion schema the 4104 script text is not in a clean
column. The `Activity` field shows the literal string `4104`, and the actual PowerShell
lives inside the `EventData` XML, which requires a brittle `extract` against
`ScriptBlockText` and gets chunked across multiple events for long scripts. `CommandLine`
on 4688 is a first-class, reliably populated column, which makes it the better foundation
for a detection. A 4104-based content rule is a documented stretch item, not the primary.

**Entity mapping:** Account (Name = `AccountUser`, NTDomain = `AccountDomain`), Host (HostName = `Computer`), Process (CommandLine = `CommandLine`)

**Custom details:** `NewProcessName`, `ParentProcessName`

**False positive sources:** legitimate administrative scripting and software deployment
frequently use `-ExecutionPolicy Bypass` and `-NoProfile`. In a real environment this
rule fires often on benign management activity, and the string list would need tuning per
environment, plus allow-listing of known-good parent processes such as SCCM or a
configuration management agent. The `ParentProcessName` custom detail exists to support
exactly that triage.

---

## Rule 4: New Account Created and Rapidly Elevated

**Technique:** T1136.001 (Create Local Account), T1098 (Account Manipulation) | **Severity:** High | **Schedule:** every 5 min, 2h lookback

Query: [`04-new-account-rapidly-elevated.kql`](../detections/04-new-account-rapidly-elevated.kql)

This is the multi-stage correlation rule and the most substantial detection in the lab.
It joins two distinct event IDs: account creation (4720) and privileged group addition
(4732), and fires only when the same account is created and then elevated within one hour
on the same host.

The join key is the account **SID**, `TargetSid` on the 4720 and `MemberSid` on the
4732, not the username. This is the whole point of the rule. Because 4732 does not carry
the member name reliably, joining on name would miss the correlation entirely. Joining on
SID links the two events correctly regardless of the missing name field. The output
includes `MinutesToElevation`, which quantifies how fast the elevation happened, a useful
triage signal since one minute between create and elevate is far more suspicious than a
same-day gap.

The scheduling lookback (2h) must match the `let lookback = 2h` inside the query. A
mismatch means the rule either misses correlations that occurred earlier in the query
window or wastes work.

**Entity mapping:** Account (Name = `NewAccountName`), Host (HostName = `Computer`)

**Custom details:** `Creator`, `GroupName`, `MinutesToElevation`

**False positive sources:** an administrator provisioning a new service or admin account
and granting it group membership in the same session. This is legitimate and looks
identical. High severity, human-confirmed. The value of the rule is not that it is
false-positive-free, it is that it collapses two separate events into one alert that
describes an attack pattern, so an analyst sees "new account elevated in one minute"
instead of an unlinked 4720 and 4732 sitting apart in the queue.

---

## A note on tuning versus the lab

Every rule above has legitimate-activity false positives, because privileged-account and
PowerShell activity is exactly what administrators do all day. In this single-DC lab there
is no benign baseline to tune against, so the thresholds are set for reliable firing on
simulated attacks. The false-positive sections describe how each rule would be tuned in a
real environment. Naming the benign triggers is the point: a detection is only finished
when its normal-environment noise is understood, not when the query returns the attack.
