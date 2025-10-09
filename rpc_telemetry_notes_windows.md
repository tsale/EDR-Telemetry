Purpose

This note explains the RPC-related telemetry entries recently added to `EDR_telem_windows.json` and suggests follow-ups for validation and enrichment.

Summary of additions

- Three new telemetry rows were added to `EDR_telem_windows.json` under a new "Telemetry Feature Category": "RPC Activity":
  1. "RPC Native Audit (Event ID 5712)" — Windows native RPC auditing event (noisy; not enabled by default).
  2. "RPC Network (Zeek / network RPC visibility)" — network-level RPC visibility, e.g., when Zeek or network sensors are present.
  3. "RPC UUID / Interface Enrichment" — enrichment of RPC activity with known UUIDs/interfaces useful to detect DCOMExec / Invoke-DCOM and other RPC-based techniques.

Why this matters

- Some adversary techniques (DCOMExec, Invoke-DCOM, advanced uses of Excel DDE, ShellWindows/ShellBrowseWindows, MMC-based activity) use RPC and DCOM pathways that can be difficult to detect reliably via process-creation heuristics or other Windows event sources.
- Native Windows RPC audit events (Event ID 5712) exist but are noisy and therefore rarely enabled in default EDR configurations.
- Enriching RPC telemetry with known UUID/interface mappings (and network-level RPC visibility) substantially improves detection fidelity for these techniques.

Conservative assumptions made

- The table entries are intentionally conservative. In many cases, an EDR vendor can surface RPC-related telemetry only if additional telemetry collection is enabled (eventlog ingestion, network sensor, or specific RPC parsing/enrichment in the backend).
- `MDE` (Microsoft Defender for Endpoint) is noted as able to provide network RPC visibility when Zeek is enabled across endpoints; this was included based on user-provided context.
- `Cybereason` was called out in the user report as having use-cases for specific RPC UUIDs; the row for UUID enrichment marks it as available (please validate with vendor).

Recommended fields to collect for RPC telemetry

- Timestamp
- Source process (PID, image, parent PID/image)
- Initiating user (if available)
- RPC Endpoint (named pipe, TCP port, etc.)
- RPC UUID / interface identifier
- Method / operation (if parsed)
- Network source/destination (for network RPC)
- Raw event source (Event ID / provider or network sensor) and raw payload reference

Suggested next steps (low-effort, high-value)

1. Validate vendor column values: open issues or contact vendor docs/rep to confirm whether they ingest 5712, network RPC, and/or support UUID enrichment.
2. Expand this repo with a curated list of known RPC UUIDs and common mappings to MITRE techniques (DCOM Exec, etc.). This will make the "RPC UUID / Interface Enrichment" row actionable.
3. Add guidance to the README about how to enable RPC-related telemetry on endpoints (links to Microsoft docs about RPC auditing and to Zeek/packet-capture deployment guides).
4. Consider adding a small dataset/example logs (sanitized) showing 5712, Zeek RPC logs, and an enriched RPC record to help detection engineering and testing.

How to validate the JSON locally (PowerShell)

Run a quick JSON parse in PowerShell to ensure the file is valid and the new entries are present:

```powershell
Get-Content .\EDR_telem_windows.json -Raw | ConvertFrom-Json | Where-Object { $_."Telemetry Feature Category" -eq 'RPC Activity' } | Format-Table -AutoSize
```

Notes and contact

If you'd like, I can:
- Open a PR with these changes and a short PR description referencing this issue.
- Add a curated starting list of RPC UUIDs and mappings (I can research and add an initial set).
- Create a small example dataset for testing detection rules.

If you prefer specific vendor corrections or want a different tone/wording for the Notes column in the JSON, tell me and I will update accordingly.
