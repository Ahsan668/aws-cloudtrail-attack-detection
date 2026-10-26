# Ingest Notes — CloudTrail → ELK

How the CloudTrail events were moved into Elasticsearch. Reproducible.

## 1. Export from AWS

AWS Console → CloudTrail → **Event history** (region **us-east-1**) → set time range to cover the attack window → **Download events → JSON**. Produces `event_history.json` as `{"Records":[ ... ]}`.

## 2. Convert to NDJSON (host, PowerShell)

Kibana's file uploader expects one JSON object per line (NDJSON). The AWS export is a single object with a nested `Records` array, so flatten it:

```powershell
cd $HOME\Downloads
(Get-Content event_history.json -Raw | ConvertFrom-Json).Records |
  ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 30 } |
  Set-Content -Encoding utf8 cloudtrail-ndjson.json
```

Verify:
```powershell
(Get-Content cloudtrail-ndjson.json).Count        # event count
Get-Content cloudtrail-ndjson.json -First 1        # one full event on one line
```

## 3. Ingest in Kibana

Kibana → **Upload a file** (Data Visualizer / Integrations) → select `cloudtrail-ndjson.json`.
- Format auto-detected: **NDJSON**
- Time field: **`eventTime`** (ISO 8601)
- Import → index name: **`cloudtrail-lab`** → create data view.

## 4. View

Discover → data view `cloudtrail-lab` → set time range to **Last 7 days** (events are historical; the default 15-minute window shows nothing).

## Notes

- Elastic trial had expired → reverted to the free **Basic** license (`POST /_license/start_basic?acknowledge=true`) before Kibana would start.
- The raw `cloudtrail-ndjson.json` is **not committed** — it contains an IAM access key **ID** that triggers secret scanning. Dashboard screenshots are the artifact.
- `.keyword` sub-fields are used wherever a text field is grouped or tabled.
