# Methodology

How every attack in this lab was run and detected, as a repeatable process.

## The loop

Each case follows the same four steps — the same loop used in on-prem SOC work, moved to the cloud's API plane:

1. **Attack** — perform an attacker action against the account (via CloudShell + AWS CLI).
2. **Telemetry** — the action is recorded automatically by CloudTrail.
3. **Detect** — find the event(s) in CloudTrail Event history; read who / what / where / when.
4. **Map & report** — map to MITRE ATT&CK, extract IOCs, write findings and response.

## Reading a CloudTrail event (the core skill)

Every CloudTrail event answers four questions:

| Question | Field |
|---|---|
| **What** happened | `eventName` |
| **Who** did it | `userIdentity` (`type`, `arn`, `principalId`) |
| **Where** from | `sourceIPAddress` |
| **When** | `eventTime` (always **UTC** — note the `Z`) |

Three more fields that carry most of the analytical value:

- **`readOnly`** — `false` = a change (action); `true` = a read (reconnaissance). The single fastest triage filter.
- **`userAgent`** — reveals the *tool and command* used (e.g. `exec-env/CloudShell ... md/command#iam.create-user`).
- **`sessionContext.attributes.mfaAuthenticated`** — whether the acting session used MFA.

## Region rule

- **IAM / STS / global services** → events always log to **us-east-1**, regardless of where the command ran. Identity attacks are investigated there.
- **Regional services** (EC2, S3 data events) → log in the region used.
- Lesson learned the hard way in this lab: CloudShell ran in `ap-southeast-2`, but the IAM attack events appeared only in `us-east-1`.

## Correlation principle

**Pivot on identity, not IP.** CloudShell assigns different AWS-pool source IPs across sessions, so the same actor appears under multiple IPs. The stable link across all events is the `principalId` / role ARN (`c408b4a8-...` / `AccountFullAccessRole`).

## Tools used

| Role | Tool |
|---|---|
| Attacker | AWS CloudShell + AWS CLI v2 |
| Telemetry | AWS CloudTrail (management events) |
| Investigation | CloudTrail Event history (console) |
| Guardrails | AWS Budgets, MFA, account-level SCPs |
