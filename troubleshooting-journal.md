# Troubleshooting Journal

This lab did not go together cleanly on the first try. Documenting the real problems here, since diagnosing them was arguably more instructive than the parts that worked as expected.

## 1. Active Directory Domain Services role installed silently incompletely

The Add Roles and Features wizard appeared to freeze during AD DS installation. After a hard reset, Server Manager showed the role installed and offered to promote the server to a domain controller, but the promotion wizard failed with an internal error: `Test-_InternalADDSVerifyForestName is not recognized`.

Running `Get-WindowsFeature AD-Domain-Services` from PowerShell revealed the role was actually **not** installed, despite what the GUI implied. The freeze during installation had left things in a broken partial state.

**Fix:** reinstalled the role directly via PowerShell (`Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools`), confirmed with `Get-WindowsFeature`, then retried the promotion wizard, which completed successfully once the role was actually present.

**Takeaway:** GUI wizards can report success based on a step completing its own internal logic, without confirming the underlying feature state. When something freezes mid-install, verify from PowerShell rather than trusting the GUI's next screen.

## 2. Azure Arc onboarding stuck on an interactive login the VM cannot complete

Running the generated onboarding script triggered an embedded browser popup inside the VM asking for "Face, fingerprint, PIN or security key." Since the VM has no biometric hardware, this could never succeed no matter how many times it was retried.

**Fix:** the default `azcmagent connect` login flow attempts interactive/WAM-based authentication on Windows, which opens this embedded browser. Adding the `--use-device-code` flag forces the older device code flow instead, which prints a code and a URL directly in the console. That URL is opened in a normal browser on a separate device, where the actual biometric/password sign-in happens successfully, and the VM picks up the completed authentication automatically.

## 3. "Invalid change token" error connecting to Azure

Once the device code flow was working, connection attempts consistently failed with `error connecting machine to Azure: invalid change token`, after the Arc resource had already been created in Azure.

Investigation with `w32tm /query /status` showed the domain controller's clock source was `Local CMOS Clock` at Stratum 1, meaning it was treating its own internal hardware clock as authoritative rather than syncing to any external time source. The VM had sat powered off over a weekend, and VirtualBox VM clocks are known to drift meaningfully during extended shutdowns. Azure's certificate-based Arc authentication is time-sensitive; even a few minutes of drift can break it.

**Fix:**
```
w32tm /config /manualpeerlist:"time.windows.com,0x8" /syncfromflags:manual /reliable:YES /update
Restart-Service w32time
w32tm /resync /force
```
This is specifically necessary on a domain controller, since promoting a server to the forest root PDC disables the normal manual time-sync toggle in Settings in favor of the domain's own time hierarchy, which does not automatically point anywhere external on a freshly created single-DC forest.

## 4. HTTP 401 "Failed to Create Resource" after fixing the clock

After correcting the clock and deleting the partially created Arc resource, a fresh connection attempt failed with a plain 401 during resource creation. This pointed to tenant resolution: the Azure account in use is a personal Microsoft account rather than one tied to an explicit organizational tenant, and `azcmagent connect` can resolve to the wrong tenant context when none is specified, especially after several prior partial connect/disconnect attempts.

**Fix:** ran `azcmagent disconnect --force-local-only` to clear local agent state, then retried `azcmagent connect` with an explicit `--tenant-id` argument pulled from the Microsoft Entra ID overview page in the portal. Connection succeeded on this attempt.

## 5. Data Collection Rule silently rejected its own query

Once the domain controller showed as Connected in Azure Arc, no data appeared in the `SecurityEvent` table, despite the Azure Monitor Agent extension showing "Succeeded," the agent process (`MonAgentCore.exe`) running, and heartbeat data confirmed flowing into Log Analytics.

The root cause turned out to be the DCR itself: text meant for a separate PowerShell log data source had been accidentally merged into the same XPath field as the Security log query, and the resulting combined string had a missing `*` after the log name as well. The agent's local log (`MonAgentHost.1.log`, found under `C:\Resources\Directory\AMADataStore.<hostname>\Configuration\`) showed the actual failure clearly:

```
Error: EventLog - MAEventTable: ErrorCode(15001): The specified query is invalid.
Message: Invalid query in the event: eventName=... query=Security![System[...]]... Will skip the query.
```

None of this appeared as an error anywhere in the Azure portal. The extension showed healthy, the DCR showed correctly associated, and the agent itself was completely functional, it had simply received an invalid query, logged it locally, and silently collected nothing.

**Fix:** corrected the XPath in the DCR's data source configuration, split the PowerShell log into its own separate data source entry rather than appending it to the Security log query, and confirmed the corrected query propagated to the agent by inspecting `mcsconfig.latest.xml` directly on the domain controller before re-checking Log Analytics.

**Takeaway:** a "healthy" status in the Azure portal only confirms the extension installed and the agent is communicating, not that the actual data collection logic is valid. When a pipeline looks fully connected but no data arrives, the agent's local configuration and log files are the authoritative source of truth, not the portal.

## 6. Path assumptions across documentation versions

Several official troubleshooting steps reference generic paths like `C:\Resources\Directory\AMADataStore\...`. On this Arc-enabled server, the actual folder is suffixed with the hostname (`AMADataStore.DC01`), which caused several `Test-Path` checks to return `False` even though the agent was actually configured correctly underneath a differently named folder. Worth checking the parent directory's actual contents rather than assuming a documented path is exact.
