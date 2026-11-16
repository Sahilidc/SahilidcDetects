# Detection Engineering Repository

A curated collection of detection rules written in **Elastic ES|QL** and **Sigma**.

This repository serves as a personal detection engineering knowledge base, covering endpoint, network, application, vulnerability, and other security-related detections.

The objective is to develop, document, test, and maintain practical detection logic mapped to the MITRE ATT&CK framework.

## Repository Structure

```text
.
├── source/
│   └── <source-name>/
│
├── ES_QL/
│   ├── APPs/
│   ├── endpoints/
│   ├── network/
│   └── cve/
│
└── Sigma/
    ├── APPs/
    ├── endpoints/
    ├── network/
    └── cve/
```

### Directory Overview

| Directory | Description |
|---|---|
| `source/` | References, research material, documentation, and original sources used to develop detections. |
| `ES_QL/` | Detection rules written using Elastic ES\|QL. |
| `ES_QL/APPs/` | Application-related detections. |
| `ES_QL/endpoints/` | Endpoint, process, and host-based detections. |
| `ES_QL/network/` | Network traffic and network security detections. |
| `ES_QL/cve/` | Detections related to known vulnerabilities and CVEs. |
| `Sigma/` | Platform-independent detection rules written in Sigma. |

## Rule Documentation Format

Every detection rule follows a consistent documentation structure.

| Field | Description |
|---|---|
| **Name** | Descriptive name of the detection rule. |
| **Description** | Explanation of the behavior, threat, or activity being detected. |
| **Log Location** | Required log source, index, or data stream. |
| **MITRE ATT&CK** | Associated MITRE ATT&CK tactic and technique IDs. |
| **Note** | Additional context, investigation guidance, limitations, and potential false positives. |
| **Query** | Actual detection logic (ES\|QL or Sigma). |

## Example: ES|QL Detection

```yaml
Name: Suspicious Encoded PowerShell Execution

Description: >
  Detects PowerShell execution involving encoded commands,
  which may indicate command obfuscation.

Log Location: logs-endpoint.events.process-*

MITRE:
  - T1059.001

Note: >
  Legitimate administrative scripts may trigger this detection.
  Validate execution context before escalating.

Query: |
  FROM logs-endpoint.events.process-*
  | WHERE event.type == "start"
    AND process.name == "powershell.exe"
    AND process.command_line LIKE "* -enc *"
```

## Detection Coverage

The repository aims to cover the following areas:

- **Endpoint Security:** Suspicious process execution, persistence, privilege escalation, and lateral movement.
- **Network Security:** Suspicious connections, unusual traffic patterns, and network-based threats.
- **Application Security:** Application abuse, suspicious authentication, and malicious application activity.
- **Vulnerability Detection:** Exploitation attempts and activity associated with known CVEs.
- **Threat Hunting:** Behavioral indicators and suspicious activity patterns.

## MITRE ATT&CK Mapping

Detection rules are mapped to the [MITRE ATT&CK](https://attack.mitre.org/) framework wherever applicable.

This helps maintain visibility into detection coverage across adversary tactics and techniques.

## Objectives

1. Build a structured collection of practical detection rules.
2. Develop detection engineering skills using ES|QL and Sigma.
3. Improve detection quality through testing and false-positive analysis.
4. Maintain references and research sources for detection development.
5. Expand coverage across endpoint, network, application, and vulnerability domains.
6. Contribute to the broader detection engineering community.

## Disclaimer

These rules are provided for research, learning, and defensive security purposes.

Detection logic should be validated against the relevant log sources and tested in a controlled environment before deployment.

Detection effectiveness depends on telemetry availability, field mappings, environment-specific configurations, and appropriate tuning.

## Author

Maintained by **Sahil**.# SahilidcDetects
