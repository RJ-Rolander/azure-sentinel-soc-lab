# Troubleshooting Journal

This lab did not go together cleanly on the first try. Documenting the real problems here,
since diagnosing them was arguably more instructive than the parts that worked as expected.

---

## 1. AD DS Role Installed Silently Incomplete

The Add Roles and Features wizard appeared to freeze during AD DS installation. After a
hard reset, Server Manager showed the role installed and offered to promote the server to
a domain controller, but the promotion wizard failed with:

```
Test-_InternalADDSVerifyForestName is not recognized.
```

Running `Get-WindowsFeature AD-Domain-Services` from PowerShell revealed the role was not
actually installed, despite what the GUI implied. The freeze during installation had left
things in a broken partial state.

**Fix:**
```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Get-WindowsFeature AD-Domain-Services  # confirm installed
```

Then retried the promotion wizard, which completed successfully once the role was actually
present.

**Takeaway:** GUI wizards can report success based on a step completing its own internal
logic without confirming the underlying feature state. When something freezes mid-install,
verify from PowerShell rather than trusting the GUI's next screen.

---

## 2. Azure Arc Onboarding Stuck on Biometric Prompt

Running the generated onboarding script triggered an embedded browser popup inside the VM
asking for a face, fingerprint, PIN, or security key. Since the VM has no biometric
hardware, this could never succeed regardless of how many times it was retried.

**Fix:** The default `azcmagent connect` login flow attempts interactive/WAM-based
authentication on Windows, which opens this embedded browser. Adding `--use-device-code`
forces the older device code flow instead, which prints a code and a URL directly in the
console. That URL is opened in a normal browser on a separate device where the actual
sign-in happens, and the VM picks up the completed authentication automatically.

```powershell
azcmagent connect --use-device-code ...
```

---

## 3. "Invalid Change Token" Error Connecting to Azure

Once the device code flow was working, connection attempts consistently failed with:

```
error connecting machine to Azure: invalid change token
```

This occurred after the Arc resource had already been created in Azure.

**Root cause:** `w32tm /query /status` showed the domain controller's clock source was
`Local CMOS Clock` at Stratum 1, meaning it was treating its own internal hardware clock
as authoritative rather than syncing to any external time source. The VM had sat powered
off over a weekend, and VirtualBox VM clocks drift meaningfully during extended shutdowns.
Azure's certificate-based Arc authentication is time-sensitive; even a few minutes of
drift can break it.

**Fix:**
```powershell
w32tm /config /manualpeerlist:"time.windows.com,0x8" /syncfromflags:manual /reliable:YES /update
Restart-Service w32time
w32tm /resync /force
```

**Note:** This is specifically necessary on a domain controller. Promoting a server to the
forest root PDC disables the normal manual time-sync toggle in Settings in favor of the
domain's own time hierarchy, which does not automatically point anywhere external on a
freshly created single-DC forest.

---

## 4. HTTP 401 "Failed to Create Resource" After Fixing the Clock

After correcting the clock and deleting the partially created Arc resource, a fresh
connection attempt failed with a plain 401 during resource creation.

**Root cause:** The Azure account in use is a personal Microsoft account rather than one
tied to an explicit organizational tenant. `azcmagent connect` can resolve to the wrong
tenant context when none is specified, especially after several prior partial
connect/disconnect attempts.

**Fix:**
```powershell
# Clear local agent state from prior attempts
azcmagent disconnect --force-local-only

# Reconnect with explicit tenant ID from Entra ID overview page
azcmagent connect --tenant-id <tenant-id-from-portal> ...
```

---

## 5. Data Collection Rule Silently Rejected Its Own Query

Once the domain controller showed as Connected in Azure Arc, no data appeared in the
SecurityEvent table despite:
- The Azure Monitor Agent extension showing "Succeeded"
- The agent process (`MonAgentCore.exe`) running
- Heartbeat data confirmed flowing into Log Analytics

**Root cause:** Text meant for a separate PowerShell log data source had been accidentally
merged into the same XPath field as the Security log query, and the combined string was
also missing a `*` after the log name. The agent's local log at:

```
C:\Resources\Directory\AMADataStore.<hostname>\Configuration\MonAgentHost.1.log
```

showed the actual failure:

```
Error: EventLog - MAEventTable: ErrorCode(15001): The specified query is invalid.
Message: Invalid query in the event: ... Will skip the query.
```

None of this appeared as an error anywhere in the Azure portal. The extension showed
healthy, the DCR showed correctly associated, and the agent itself was completely
functional. It had simply received an invalid query, logged it locally, and silently
collected nothing.

**Fix:** Corrected the XPath in the DCR's data source configuration and split the
PowerShell log into its own separate data source entry. Confirmed the corrected query
propagated to the agent by inspecting `mcsconfig.latest.xml` directly on the domain
controller before re-checking Log Analytics.

**Takeaway:** A "healthy" status in the Azure portal only confirms the extension installed
and the agent is communicating, not that the actual data collection logic is valid. When a
pipeline looks fully connected but no data arrives, the agent's local configuration and log
files are the authoritative source of truth, not the portal.

---

## 6. Path Assumptions Across Documentation Versions

Several official troubleshooting steps reference generic paths like:

```
C:\Resources\Directory\AMADataStore\...
```

On this Arc-enabled server, the actual folder is suffixed with the hostname
(`AMADataStore.DC01`), which caused several `Test-Path` checks to return `False` even
though the agent was correctly configured underneath a differently named folder.

**Fix:** Check the parent directory's actual contents rather than assuming a documented
path is exact:

```powershell
Get-ChildItem "C:\Resources\Directory\" | Where-Object { $_.Name -like "AMADataStore*" }
```

---

## 7. Analytics Rule Produced Correct Results but Zero Entities

After building the four scheduled analytics rules, the first brute-force incident showed
`Assets (0)` and, on the incident graph, "No entities to display." The Related Events
table on the same incident showed everything correctly: `IpAddress 10.0.2.6`,
`Computer DC01.soclab.local`, and the custom details (`FailedCount 6`,
`TargetedAccounts ["Administrator"]`). The detection fired and the query output was right.
The incident had no entities.

**Root cause:** Entity mapping was never added to the rules during creation. The rule ran,
matched, and produced correct rows, but with no entity mapping configured there was nothing
to bind those rows to as pivotable entities. Entity binding is independent of query output.
A rule can return perfectly shaped data and still attach zero entities.

**Fix:** Opened each rule (Set rule logic > Alert enhancement > Entity mapping) and added
the mappings. For the brute-force rule, IP (Address = `IpAddress`) and Host
(HostName = `Computer`). A related error surfaced while doing this: mapping an Account
entity with only an `NTDomain` identifier throws

```
Invalid Identifiers, can be any of the combinations: (FullName) OR (Sid) OR (Name) OR (AadUserId) OR (PUID) OR (ObjectGuid)
```

`NTDomain` is a qualifier, not a standalone identifier. It has to sit on the same Account
entity alongside a `Name` (or SID, etc.) as a second identifier, not as its own entity.

Entity mapping binds at alert creation and does not backfill. Existing incidents stayed
entity-less permanently. Verifying the fix required generating a fresh alert and confirming
`Assets > 0` on the new incident, not re-checking the old one.

**Takeaway:** "Query returns rows" is not "incident is investigable." Without entity mapping
an analyst gets no pivotable entities, no automatic enrichment, and no entity-based
correlation, even though the rule technically worked. Verify entities on a live incident,
not just query output. This distinction is the difference between writing a query and
engineering a detection, and it is invisible until an incident is open in front of you.

---

## 8. Azure Monitor Agent Has No `AzureMonitorAgent` Service on Arc Installs

After the DC had been powered off for a day, a health check for the agent service failed:

```
Get-Service : Cannot find any service with service name 'AzureMonitorAgent'.
```

The Arc agent (`himds`) was running fine, so Arc itself was healthy and only the monitoring
layer looked broken.

**Root cause:** There is no standalone `AzureMonitorAgent` Windows service on an
extension-based (Arc) install. That service name belongs to the standalone MSI installer
path used on Windows 10/11 clients. On an Arc machine the agent runs as a set of processes,
not that named service.

**Fix:** Check for the agent processes instead of a service:

```powershell
Get-Process Mon* -ErrorAction SilentlyContinue
```

The correct healthy state is four running processes: `MonAgentCore`, `MonAgentHost`,
`MonAgentLauncher`, and `MonAgentManager`. `MonAgentCore` is the component that collects
event logs and streams to Log Analytics. All four were present, so the agent was never
actually broken. The earlier `Events (0)` shown on the portal's data connectors card was
just the rolling 24-hour window being empty while the VM was off.

**Takeaway:** The same product ships two install paths with two different verification
steps. A missing service name is not a missing agent. Confirm which install path is in use
before concluding the agent is down.

---

## 9. Event 4104 Script Block Text Is Not in a Queryable Column

While building the suspicious-PowerShell detection, the plan was to match on 4104 script
block content. Inspecting an actual 4104 row showed the `Activity` column contains the
literal string `4104`, not the script. The real PowerShell content sits inside the
`EventData` column as XML:

```
<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">...
```

**Root cause:** On this ingestion schema, PowerShell Operational events routed into the
`SecurityEvent` table do not get the script block promoted to a first-class column.
Extracting it requires a regex against `ScriptBlockText` inside the XML, and long scripts
are chunked across multiple 4104 events, which makes the extract brittle.

Confirmed the routing with:

```kql
union withsource=SourceTable SecurityEvent, Event
| where TimeGenerated > ago(24h)
| where EventID == 4104
| summarize count() by SourceTable
```

which returned 4104 only under `SecurityEvent`, with zero rows in `Event`.

**Fix:** Anchored the detection on the 4688 `CommandLine` column instead, which is
first-class and reliably populated. The 4104-based content rule is kept as a documented
stretch item rather than the primary detection.

**Takeaway:** Do not assume an event field carries what its name suggests. The `Activity`
column name implied it held the script; it did not. Inspect a real row before building a
detection on top of a field.
