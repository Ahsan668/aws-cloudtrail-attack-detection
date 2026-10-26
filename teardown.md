# Teardown / Cleanup

Run after capturing all evidence. Removes the artifacts created during the lab so nothing lingers (and any leaked key screenshot becomes useless once the key is deleted).

## 1. Delete the rogue user's access keys

List the keys, then delete each one:

```bash
aws iam list-access-keys --user-name backdoor-admin
aws iam delete-access-key --user-name backdoor-admin --access-key-id <AccessKeyId>
```

## 2. Detach the admin policy

```bash
aws iam detach-user-policy --user-name backdoor-admin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

## 3. Delete the rogue user

```bash
aws iam delete-user --user-name backdoor-admin
```

## 4. Confirm it's gone

```bash
aws iam list-users          # backdoor-admin should no longer appear
```

## 5. Account hygiene (keep these ON — they are not lab artifacts)

- MFA on root and daily login — **keep**
- AWS Budgets alert — **keep**
- GuardDuty — never enabled (blocked by Free-plan / SCP), nothing to disable

## Notes

- IAM user deletion can fail if the user still has attached policies, keys, login profiles, or inline policies — remove those first (steps 1–2), then delete.
- CloudTrail history is retained by AWS regardless — the evidence captured in this repo is the record; the live resources are removed.
