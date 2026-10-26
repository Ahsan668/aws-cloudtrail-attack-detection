# Attack 01 — Rogue IAM User (Persistence Backdoor)

## Summary

| | |
|---|---|
| **Verdict** | Malicious — confirmed |
| **Severity** | High |
| **Tactic** | Persistence (TA0003) |
| **Techniques** | T1136.003 Create Account: Cloud Account · T1098 Account Manipulation |
| **Actor** | `AccountFullAccessRole` (assumed role, SSO session), userId `c408b4a8-a0a1-706e-35e3-5e2d6f56519b` |
| **Date** | 2026-10-25 (UTC) |

**One line:** An attacker inside the account created a new IAM user (`backdoor-admin`) and attached `AdministratorAccess` to it, establishing a persistent, independent way back in.

---

## Scenario

Assume the attacker has already gained access (e.g. a leaked access key — *Initial Access, assumed*). Their first priority is **persistence**: a way to return even if the original access is revoked. The standard move is to create a fresh IAM user they control and give it full admin rights.

---

## Attack steps (attacker side)

Run from AWS CloudShell:

```bash
aws iam create-user --user-name backdoor-admin
aws iam attach-user-policy --user-name backdoor-admin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backdoor-admin   # key redacted — deleted at teardown
```

`[SCREENSHOT: CloudShell showing create-user + attach-user-policy output]`

---

## Detection (analyst side)

Source: **CloudTrail → Event history**, region **us-east-1** (IAM is global → logs land here regardless of CloudShell's region — a key lesson: *watch us-east-1 for identity attacks*).

Filter: `Event name = CreateUser`, then `Event name = AttachUserPolicy`.

### Event 1 — CreateUser
```json
{
  "eventName": "CreateUser",
  "eventTime": "2026-10-25T20:33:53Z",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "16.178.25.21",
  "userIdentity": { "type": "AssumedRole", "arn": ".../AccountFullAccessRole/c408b4a8-..." },
  "requestParameters": { "userName": "backdoor-admin" },
  "responseElements": { "user": { "arn": "arn:aws:iam::437845271152:user/backdoor-admin",
                                   "userId": "AIDAWL4M4UJYFZMUUQGQD" } },
  "readOnly": false,
  "userAgent": "... exec-env/CloudShell ... md/command#iam.create-user",
  "sessionContext": { "attributes": { "mfaAuthenticated": "false" } }
}
```
`[SCREENSHOT: CloudTrail CreateUser event — raw JSON]`

### Event 2 — AttachUserPolicy
```json
{
  "eventName": "AttachUserPolicy",
  "eventTime": "2026-10-25T20:37:10Z",
  "requestParameters": { "userName": "backdoor-admin",
                         "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess" },
  "readOnly": false,
  "userAgent": "... exec-env/CloudShell ... md/command#iam.attach-user-policy",
  "sessionContext": { "attributes": { "mfaAuthenticated": "false" } }
}
```
`[SCREENSHOT: CloudTrail AttachUserPolicy event — raw JSON]`

---

## Timeline

```
20:33:53Z  CreateUser        → backdoor-admin created
20:37:10Z  AttachUserPolicy  → AdministratorAccess attached (+3m17s)
```

---

## Analyst observations

1. **The sequence is the signal.** `CreateUser` alone is low-risk (a permission-less user is harmless). `CreateUser` *followed within minutes by* `AttachUserPolicy` granting admin is high-risk. Detection logic should alert on the **pattern**, not the individual event.
2. **No MFA.** Both privileged actions ran with `mfaAuthenticated: false`.
3. **Origin obscured.** Source IP `16.178.25.21` is AWS-internal (CloudShell), hiding the attacker's true location. `userAgent` still disclosed the exact CLI command.
4. **`readOnly: false`** on both — these were state-changing actions.

---

## Indicators (IOCs)

| Type | Value |
|---|---|
| Created user ARN | `arn:aws:iam::437845271152:user/backdoor-admin` |
| Created userId | `AIDAWL4M4UJYFZMUUQGQD` |
| Actor role | `arn:aws:iam::437845271152:role/managed/AccountFullAccessRole` |
| Actor session userId | `c408b4a8-a0a1-706e-35e3-5e2d6f56519b` |
| Source IP | `16.178.25.21` (AWS CloudShell) |

---

## Recommended SOC response

- **Detect:** Alert on `CreateUser` followed by `AttachUserPolicy` (esp. `AdministratorAccess`) from the same principal within a short window.
- **Contain:** Delete/disable the rogue user and its access keys; revoke the acting session.
- **Prevent:** Enforce MFA on all privileged principals; use SCPs/permission boundaries to restrict who can create users and attach admin policies; require change-approval for IAM modifications.
