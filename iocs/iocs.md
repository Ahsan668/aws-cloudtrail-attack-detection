# Indicators of Compromise (IOCs)

All indicators observed across the lab. In a real investigation these would be fed to a SIEM / threat-hunting tool to sweep for related activity.

## Identities

| Type | Value | Context |
|---|---|---|
| Acting role | `arn:aws:iam::437845271152:role/managed/AccountFullAccessRole` | The compromised/abused admin role |
| Acting session userId | `c408b4a8-a0a1-706e-35e3-5e2d6f56519b` | Stable actor pivot across all events |
| Rogue user ARN | `arn:aws:iam::437845271152:user/backdoor-admin` | Persistence backdoor created in Attack 01 |
| Rogue userId | `AIDAWL4M4UJYFZMUUQGQD` | — |

## Source IPs (AWS CloudShell — origin obscured)

| IP | Seen in |
|---|---|
| `16.178.25.21` | Attack 01 (CreateUser, AttachUserPolicy) |
| `3.107.204.138` | Attack 02 (enumeration) |

> Both are AWS-internal CloudShell addresses — they do **not** reveal the attacker's true location. Listed as weak indicators only; correlate on identity instead.

## Suspicious API events

| Event | Attack | readOnly |
|---|---|---|
| `CreateUser` | 01 — Persistence | false |
| `AttachUserPolicy` (AdministratorAccess) | 01 — Persistence | false |
| `GetCallerIdentity` | 02 — Discovery | true |
| `ListUsers` | 02 — Discovery | true |
| `ListRoles` | 02 — Discovery | true |
| `ListAttachedUserPolicies` | 02 — Discovery | true |

## MITRE ATT&CK coverage

| Technique | Name | Tactic |
|---|---|---|
| T1136.003 | Create Account: Cloud Account | Persistence |
| T1098 | Account Manipulation | Persistence |
| T1087.004 | Account Discovery: Cloud Account | Discovery |
| T1069.003 | Permission Groups Discovery: Cloud Groups | Discovery |
