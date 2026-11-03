# Detection 002 — PowerShell Execution Monitoring

## Overview

This detection scenario focuses on monitoring PowerShell process execution using **Sysmon and Wazuh**, with particular attention to Base64-encoded commands.

The lab covers custom detection rule development, alert analysis, validation testing, and the identification and remediation of a detection coverage gap in the existing Wazuh ruleset.

**Key outcome:** Identified limitations in the existing encoded PowerShell detection logic and implemented a custom rule to improve coverage across different parent processes and command-line arguments.

## Lab Environment

| Component | Technology |
|---|---|
| SIEM / Detection Engine | Wazuh 4.14 |
| Endpoint | Windows 11 Pro |
| Telemetry | Sysmon — Event ID 1 (Process Creation) |
| Wazuh Server | Ubuntu Server 24.04 LTS |
| Virtualization | Oracle VirtualBox |
| MITRE ATT&CK | T1059.001 — PowerShell |

## Phase 1 — Basic PowerShell Monitoring

**Objective:** Verify PowerShell process creation telemetry and implement a custom detection rule.

A controlled PowerShell command was executed:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'SOC-LAB-TEST-002'"
```

Sysmon recorded the process creation event, which was forwarded to Wazuh for analysis.

Custom rule **100002 (Level 8)** was implemented to identify the test marker within the process command line.

**Result:** Successful detection and alert generation.

- [Custom Rule 100002](rules/rule-100002.xml)
- [Wazuh Alert 100002](alerts/alert-100002.json)

## Phase 2 — Encoded PowerShell Execution

**Objective:** Detect PowerShell execution using the `-EncodedCommand` argument.

A Base64-encoded test command was generated and executed:

```powershell
$command = "Write-Output 'SOC-LAB-ENCODED-002'"
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($command)
)
powershell.exe -NoProfile -EncodedCommand $encoded
```

The execution triggered Wazuh's built-in rule **92057**, which detects encoded PowerShell execution under specific conditions.

Custom rule **100003 (Level 13)** was implemented as a child of rule 92057 to provide a dedicated alert for the tested `-EncodedCommand` pattern.

**Result:** Successful detection with MITRE ATT&CK mapping to **T1059.001**.

- [Custom Rule 100003](rules/rule-100003.xml)
- [Wazuh Alert 100003](alerts/alert-100003.json)

## Phase 3 — Detection Gap Analysis & Remediation

### Detection Gap Identification

Additional tests were performed to evaluate the detection coverage of the existing Wazuh rule.

Analysis of built-in rule **92057** revealed a dependency on the parent process:

```xml
<field name="win.eventdata.parentImage" type="pcre2">(?i)powershell\.exe</field>
```

The rule also used a command-line expression that did not explicitly include the exact `-enc` abbreviation.

During testing:

- PowerShell execution with `-enc` generated a general process alert (`92027`), rather than the expected encoded-command detection.
- Encoded PowerShell execution launched from `cmd.exe` was recorded by Sysmon, but the expected specialized alert was not observed.

These findings demonstrated limitations in the tested detection coverage. The original CMD event's ingestion into the Wazuh analysis engine was not independently confirmed.

### Remediation — Custom Rule 100004

Custom rule **100004 (Level 12)** was implemented to detect encoded PowerShell execution without requiring a specific parent process.

The rule evaluates:

- Sysmon Event ID 1 process creation events.
- PowerShell executable paths.
- The `-EncodedCommand` and `-enc` command-line arguments.

This extends detection coverage to the tested CMD-launched PowerShell scenarios.

### Validation Results

| Test Scenario | Expected Result | Status |
|---|---|---|
| PowerShell → `-EncodedCommand` | Rule 100003 | PASS |
| Normal PowerShell execution | No rule 100003 alert | PASS |
| CMD → `-EncodedCommand` | Rule 100004 | PASS |
| CMD → `-enc` | Rule 100004 | PASS |
| CMD → normal PowerShell | No rule 100004 alert | PASS |

The tests confirmed that rule 100004 detected both encoded-command variants launched from CMD without triggering on the tested normal PowerShell command.

**Result:** Improved detection coverage, validated through controlled positive and negative test cases.

- [Custom Rule 100004](rules/rule-100004.xml)
- [Wazuh Alert 100004](alerts/alert-100004.json)

## Evidence

The following screenshots document the detection workflow and validation results.

| Evidence | Description |
|---|---|
| [Basic Execution](screenshots/01-basic-execution.png) | Controlled PowerShell execution |
| [Basic Detection](screenshots/02-basic-alert.png) | Custom rule 100002 alert |
| [Encoded Command](screenshots/03-encoded-command.png) | Encoded PowerShell execution |
| [Encoded Command Alert](screenshots/04-encoded-alert.png) | Custom rule 100003 alert |
| [Detection Gap Analysis](screenshots/05-detection-gap-analysis.png) | Original Wazuh rule 92057 conditions |
| [Remediation Alert](screenshots/06-remediation-alert.png) | Successful rule 100004 detection |

## Limitations

- All tests were performed in an isolated lab environment using controlled commands.
- Encoded PowerShell execution is not inherently malicious; legitimate administrative activity may use the same arguments.
- The custom rules were validated against selected scenarios, not every PowerShell argument abbreviation, execution method, or evasion technique.
- Additional testing and tuning would be required before production deployment.

## Key Takeaways

This scenario provided practical experience in:

- Windows endpoint telemetry collection and Sysmon event analysis.
- Wazuh custom rule development and validation.
- PowerShell execution monitoring and MITRE ATT&CK mapping.
- Identifying detection coverage gaps in existing security rules.
- Implementing and testing detection improvements.

**Outcome:** Three custom Wazuh rules developed and tested, including a remediation rule that successfully detected previously uncovered encoded PowerShell execution scenarios.