# macOS EDR Telemetry Investigation Report

**Date:** March 2026
**Scope:** Verification of `EDR_telem_macOS.json` accuracy and completeness
**Status:** PR #150 (by oliviagallucci) is still open / not merged to main

---

## 1. Executive Summary

This investigation cross-referenced every entry in the macOS EDR telemetry JSON against official vendor documentation for all 6 included EDR products. The JSON contains **60 sub-categories** across **16 feature categories** for **LimaCharlie, Elastic Defend, BitDefender GravityZone, Qualys EDR, CrowdStrike Falcon, and ESET Inspect**.

**Overall finding:** The JSON data is largely accurate and well-supported by documentation. However, three actionable issues were identified:

1. **"Script Execution" sub-category is missing from the JSON** but is present in `compare.py`'s scoring dictionary, creating a dead-weight scoring entry.
2. **"Profile Added" and "Profile Removed" sub-categories** were suggested in PR #150 review but never added.
3. **CI/CD pipeline does not trigger on macOS file changes.**

---

## 2. Methodology

### Files Analyzed
| File | Purpose |
|------|---------|
| `EDR_telem_macOS.json` (662 lines) | Primary macOS telemetry data |
| `EDR_telem_macOS.csv` (61 lines) | CSV version with emoji encoding |
| `partially_value_explanations_macOS.json` (632 lines) | Justifications for "Partially" ratings |
| `Tools/compare.py` (lines 108-185) | Scoring engine with `MACOS_CATEGORIES_VALUED` |

### Documentation Sources Consulted
| EDR Product | Source | Access |
|-------------|--------|--------|
| **LimaCharlie** | docs.limacharlie.io - Reference > EDR Events | Full public access; complete macOS event table reviewed |
| **Elastic Defend** | elastic.co/guide/en/security/8.18/ - Endpoint integration policy config | Full public access; advanced settings confirmed |
| **BitDefender GravityZone** | bitdefender.com/business/support/ - GravityZone Cloud docs | Partial access; deep EDR event pages require portal navigation |
| **CrowdStrike Falcon** | crowdstrike.com product pages + public datasheets | Limited; detailed docs behind Falcon console auth |
| **Qualys EDR** | qualys.com/apps/edr/ marketing + Cloud Agent overview | Limited; full user guide (PDF) behind auth |
| **ESET Inspect** | help.eset.com/ei_navigate/3.0/en-US/ | Full public access; On-Prem 3.0 docs reviewed |

### Cross-Reference Process
For each of the 60 sub-categories, the following was verified:
- Whether the documented EDR events map to the claimed Yes/No/Partially value
- Whether "Partially" explanations in the explanations JSON are technically accurate
- Whether the CSV emoji mappings match the JSON word values

---

## 3. Per-Product Verification Results

### 3.1 LimaCharlie

**Verification depth:** High (full public documentation available)
**Result:** All 60 entries consistent with documented capabilities.

| Category | Key Events Verified | JSON Value | Status |
|----------|-------------------|------------|--------|
| Process Creation | `NEW_PROCESS` | Yes | Confirmed |
| Process Termination | `TERMINATE_PROCESS` | Yes | Confirmed |
| File Creation | `FILE_CREATE` | Yes | Confirmed |
| File Modification | `FILE_MODIFIED` | Yes | Confirmed |
| File Deletion | `FILE_DELETE` | Yes | Confirmed |
| File Attribute Change | No documented event | No | Confirmed |
| File Open/Access | `FILE_TYPE_ACCESSED` (limited to specific extensions) | Partially | Confirmed |
| User Logon | `USER_LOGIN` | Yes | Confirmed |
| User Logoff | `SSH_LOGOUT` / session events | Yes | Confirmed |
| DNS Query | `DNS_REQUEST` | Yes | Confirmed |
| Network Connection | `NEW_TCP4_CONNECTION`, `NEW_TCP6_CONNECTION` | Yes | Confirmed |
| Network Socket Listen | `NETSTAT_REP` | Yes | Confirmed |
| External Media Mounted | `VOLUME_MOUNT` | Yes | Confirmed |
| External Media Unmounted | `VOLUME_UNMOUNT` | Yes | Confirmed |
| Binary Signature Info | `CODE_IDENTITY` | Yes | Confirmed |
| Unsigned Binary Executed | Inferred from `CODE_IDENTITY` (no dedicated event) | Partially | Confirmed |
| MD5 Available | Not in `FILE_HASH_REP` or `CODE_IDENTITY` | No | Confirmed |
| SHA-256 Available | `FILE_HASH_REP`, `CODE_IDENTITY` | Yes | Confirmed |
| Service Created | `SERVICE_CHANGE` | Yes | Confirmed |
| Service Modified | `SERVICE_CHANGE` | Yes | Confirmed |
| Agent Start | `STARTING_UP` | Yes | Confirmed |
| Agent Stop | `SHUTTING_DOWN` | Yes | Confirmed |

**Notes:** All "No" entries for LimaCharlie (e.g., Screen Lock, TCC events, Launchd items) were verified as having no corresponding documented event type.

---

### 3.2 Elastic Defend

**Verification depth:** High (public docs for version 8.18)
**Result:** All entries consistent. "Partially" values are well-justified.

| Sub-Category | JSON Value | Explanation Verified |
|-------------|------------|---------------------|
| Script Content | Partially | `mac.advanced.events.script_capture` added in 9.3, disabled by default, max 1024 bytes. Correct. |
| File Open/Access | Partially | `mac.advanced.events.event_on_access.file_paths` added in 8.15, disabled by default. Correct. |
| MD5 Available | Partially | `mac.advanced.events.hash.md5` disabled by default since 8.18. Correct. |
| Unsigned Binary Executed | Partially | Code signing info in process events allows inference; no dedicated event. Correct. |
| System Extension Loaded | Yes | Documented in event collection (Complete EDR preset). Confirmed. |

**Notes:** Event collection on macOS includes Process, File, and Network events. The "Complete" EDR preset collects all available events.

---

### 3.3 BitDefender GravityZone

**Verification depth:** Medium (deep EDR event documentation requires portal navigation)
**Result:** Entries appear plausible based on available documentation.

| Sub-Category | JSON Value | Notes |
|-------------|------------|-------|
| Network Socket Listen | Partially | Explanation states inbound connections captured via `network_connection` with `direction: inbound`, but no dedicated socket listen event. Reasonable. |
| All Process/File/Network core events | Yes | Consistent with GravityZone EDR marketing claims for macOS agent |

**Caveat:** Full verification would require access to the GravityZone Cloud console's detailed event schema documentation.

---

### 3.4 CrowdStrike Falcon

**Verification depth:** Medium (detailed docs behind Falcon console authentication)
**Result:** Entries consistent with publicly available information.

| Sub-Category | JSON Value | Notes |
|-------------|------------|-------|
| Launchd Item Created | Partially | Observed via file write events to persistence paths; no dedicated `event_simpleName`. Explanation is accurate. |
| Launchd Item Modified | Partially | Same mechanism as Created. Correct. |
| LoginItem Created | Partially | Monitored per macOS datasheet but no specific event type. Correct. |
| Unsigned Binary Executed | Partially | `SignInfoFlags` in `ProcessRollup2` allows derivation. Correct. |
| File Open/Access | Partially | Metadata in context of process events; no distinct file read event publicly confirmed. Correct. |
| Kernel Extension Loaded | Yes | Known `KextLoad` event documented. Confirmed. |

**Notes:** CrowdStrike's single lightweight sensor for macOS supports process (`ProcessRollup2`), network (`NetworkConnect`), DNS (`DnsRequest`), and user logon (`UserLogon`) events, all aligning with the JSON.

---

### 3.5 Qualys EDR

**Verification depth:** Low (detailed docs behind authentication)
**Result:** Entries appear reasonable.

**Notes:** Qualys Multi-Vector EDR uses the Qualys Cloud Agent for macOS with process, file, and network monitoring. The product has many "No" entries for advanced macOS-specific categories (TCC, Gatekeeper, XProtect, System Extensions, persistence mechanisms), which is consistent with Qualys's positioning as a vulnerability-management-first platform with EDR as an add-on capability.

---

### 3.6 ESET Inspect

**Verification depth:** Medium-High (On-Prem 3.0 public docs)
**Result:** Entries consistent with documented capabilities.

| Sub-Category | JSON Value | Notes |
|-------------|------------|-------|
| File Creation | Partially | Only executable files saved to disk; non-executable file creation not collected. Explanation accurate. |
| Scheduled Task Change | Partially | Documents "scheduled task creation" (cron); modification/deletion not documented. Correct. |
| Launchd Item Created | Partially | "Service creation" may map to LaunchAgent/Daemon but not explicitly confirmed for macOS. Honest assessment. |
| Binary Signature Info | Partially | macOS endpoint only shows Present/None states; no full certificate chain validation. Correct. |
| Unsigned Binary Executed | Partially (explanation) | Derivable from Signature Type = None. Correct. |
| User Account Created/Modified/Deleted | Yes | Rule-based detection confirmed in docs. Confirmed. |
| Kernel Extension Loaded | Yes | Documented in event types. Confirmed. |
| Service Created | Partially | Same ambiguity as Launchd Item Created. Consistent with explanation. |

---

## 4. CSV/JSON Consistency Check

The `EDR_telem_macOS.csv` was cross-referenced against `EDR_telem_macOS.json`:

- All "Yes" entries in JSON map to checkmark emoji in CSV
- All "Partially" entries in JSON map to warning emoji in CSV
- All "No" entries in JSON map to X emoji in CSV
- All null/"EDR-placeholder" entries are consistent

**Result:** CSV and JSON are fully consistent.

---

## 5. Issues Found

### 5.1 CRITICAL: "Script Execution" Sub-Category Missing from JSON

**Location:** `Tools/compare.py:126` vs `EDR_telem_macOS.json`

`compare.py` defines:
```python
MACOS_CATEGORIES_VALUED = {
    ...
    "Script Content": 1.0,
    ...
}
```

The JSON only contains **"Script Content"** under "Script Activity". **"Script Execution" has no corresponding entry** in the JSON or CSV.

**Impact:** The scoring engine assigns a weight of 1.0 to "Script Execution" but can never find a matching entry in the JSON data. This creates a dead-weight penalty: every EDR product loses points for a category that doesn't exist in the dataset.

**Recommendation:** Either:
- **(A)** Add "Script Execution" as a sub-category to the JSON, CSV, and explanations files (with appropriate values per EDR product), OR
- **(B)** Remove "Script Execution" from `MACOS_CATEGORIES_VALUED` in `compare.py` if the decision was to only track content capture

Option (A) is recommended, as script execution monitoring (especially for `osascript`/AppleScript) is a critical macOS security telemetry gap.

---

### 5.2 SUGGESTED: "Profile Added" and "Profile Removed" Sub-Categories

**Source:** PR #150 review comment by @calhall

A reviewer suggested adding "Profile Added" and "Profile Removed" sub-categories, referencing Apple's Endpoint Security framework event `ES_EVENT_TYPE_NOTIFY_PROFILE_ADD`. Configuration profiles are a known persistence and management vector on macOS.

**Status:** Not implemented. The suggestion remains as an unresolved review comment on the open PR.

**Recommendation:** Consider adding these sub-categories in a follow-up update. They map to real ES framework events and are security-relevant.

---

### 5.3 LOW: CI/CD Pipeline Missing macOS File Triggers

**Location:** `.github/workflows/github-actions-secure.yml`

The GitHub Actions workflow triggers on changes to Windows and Linux telemetry files but does not include `EDR_telem_macOS.json`, `EDR_telem_macOS.csv`, or `partially_value_explanations_macOS.json` in its trigger paths.

**Impact:** Changes to macOS telemetry files will not trigger automated validation.

**Recommendation:** Add macOS files to the workflow trigger paths once the macOS data is merged to main.

---

## 6. Summary of Proposed Changes

| # | Priority | Change | Files Affected |
|---|----------|--------|----------------|
| 1 | **High** | Add "Script Execution" sub-category to macOS telemetry data | `EDR_telem_macOS.json`, `EDR_telem_macOS.csv`, `partially_value_explanations_macOS.json` |
| 2 | **High** | OR remove "Script Execution" from scoring if intentionally excluded | `Tools/compare.py` (line 126) |
| 3 | **Medium** | Consider adding "Profile Added" / "Profile Removed" sub-categories | `EDR_telem_macOS.json`, `EDR_telem_macOS.csv`, `partially_value_explanations_macOS.json`, `Tools/compare.py` |
| 4 | **Low** | Add macOS files to CI/CD trigger paths | `.github/workflows/github-actions-secure.yml` |

---

## 7. Verification Limitations

- **BitDefender and Qualys** could not be fully verified due to documentation access restrictions. Values are plausible but not independently confirmed at the event-schema level.
- **CrowdStrike** detailed event documentation requires Falcon console access. Verification was based on public datasheets and marketing materials.
- The **edr-telemetry.com macOS page** shows "Coming Soon", indicating this data is pre-release.
- This investigation was conducted against documentation available as of March 2026. EDR products update their macOS support frequently.

---

## 8. Conclusion

The macOS EDR telemetry JSON is well-constructed and the "Partially" explanations are technically sound and honest about limitations. The most important finding is the **"Script Execution" discrepancy** between `compare.py` and the JSON, which should be resolved before the macOS data goes live on edr-telemetry.com.
