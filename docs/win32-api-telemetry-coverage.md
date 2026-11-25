# Windows Win32 API Telemetry coverage audit

November 25, 2026. Scope: the Windows matrix's 24 product/tool columns. Count first-party, analyst-visible endpoint records identifying the API call as telemetry. An alert that refers to an API, a management REST API, or a record of the resulting process/file/network action alone does not qualify. Do not infer coverage of all Windows APIs from an event family.

| Existing pending entry | Finding | Proposed status |
| --- | --- | --- |
| Trellix | The [EDR Device Search guide](https://docs.trellix.com/v1/docs/search-for-historical-data-on-a-single-endpoint) documents a dedicated Windows API-calls results bucket. The [EDR Historical Search guide](https://docs.trellix.com/docs/investigate-endpoint-telemetry-with-historical-search) confirms endpoint-store records with API activity, including function names and arguments. Documentation evidence; exact agent and policy coverage were not exercised. | Yes (documented, not independently retested) |
| Trend Micro | [PR #181](https://github.com/tsale/EDR-Telemetry/pull/181) already proposes Yes and includes Windows Endpoint Sensor search evidence for the dedicated API-invocation event (14/1102). Keep the change in that PR to avoid duplicating the vendor rename and evidence. | Pending on main; Yes proposed in #181 |
| CrowdStrike | The [Falcon Event Streams guide](https://www.crowdstrike.com/wp-content/uploads/2022/12/CrowdStrike-Falcon-Event-Streams-Add-on-Guide-v3.pdf) does not establish a huntable Windows API-call event. A Falcon endpoint event schema or sample is still needed. | Pending Response |
| Cybereason | No first-party, analyst-visible named Windows API event was verified. Detection and Windows Event Log collection are not substitutes. | Pending Response |
| FortiEDR | The [Threat Hunting guide](https://docs.fortinet.com/document/fortiedr/7.0.0/administration-guide/177933/threat-hunting) describes search, but does not establish a named Windows API-call event. | Pending Response |
| Harfanglab | The [vendor EDR documentation](https://harfanglab.io/edr/) describes access to endpoint events but does not establish a named Windows API-call event. | Pending Response |
| LimaCharlie | The [endpoint sensor event catalog](https://docs.limacharlie.io/8-reference/edr-events/) does not establish a dedicated named Windows API-call event. Related endpoint signals and ingested Windows logs are separate. | Pending Response |
| Qualys | The [EDR event-type reference](https://docs.qualys.com/en/edr/latest/search_tips/tokens_for_event_type.htm) does not establish a named Windows API-call event. | Pending Response |
| SentinelOne | The [Deep Visibility event inventory](https://go.sentinelone.com/rs/327-MNM-087/images/pdf-from-hunt-to-action-webinar.pdf) describes specific process interactions and behavioral indicators, but does not establish independently searchable named API calls. A current Event Search example would resolve this. | Pending Response |
| Symantec SES Complete | [Broadcom](https://docs.broadcom.com/doc/endpoint-detection-and-response-atp-endpoint-en) describes detection using specific Windows API calls. That does not confirm those calls are separately visible as endpoint records in SES Complete. | Pending Response |

Keep the four existing No and two existing Partially ratings unchanged. Missing public evidence is not a verified negative. For unresolved products, look for a vendor event schema with an API name field, a representative analyst-visible event, or clearly scoped direct test evidence.

## Scoring decision

The category is already visible on the Windows matrix. The [public scoring methodology](https://www.edr-telemetry.com/scores#optional-telemetry) requires 75% support across the scoped vendor set; only Yes and Via EnablingTelemetry count toward that threshold. Across the current 24 columns, the baseline is 8/24, this PR would make it 9/24, and #181 would bring it to 10/24. Even excluding Sysmon as a non-vendor comparator, that would be 10/23. Do not promote it to scored status in this PR.
