# Telemetry Operations (Syscall/API Only)

This document describes what each telemetry event does and how it triggers the activity using syscalls and native macOS framework APIs (no execution of macOS utilities).

## Process Activity

- ProcessCreation: forks a child process, waits for it to exit; generates process lifecycle telemetry.
- ProcessTermination: forks a child process and terminates it with a signal; generates termination telemetry.
- PrivilegeEscalation: attempts privilege transitions by changing effective UID/GID; generates set*id syscall telemetry (success or permission failure).

## File Activity

- FileCreation: creates a new file and writes initial bytes using direct file syscalls.
- FileModification: appends bytes to an existing file using direct file syscalls.
- FileDeletion: removes a file via unlink semantics.
- FileAttributeChange: changes file mode/permissions via chmod semantics.
- ExtendedAttributes: sets/reads/removes a custom extended attribute on a file.
- FileOpenAccess: opens an existing file read-only and reads bytes (no modification) to generate file open/access telemetry.

## Network Activity

- NetworkConnection: creates an outbound TCP connection to a known IP/port using sockets.
- NetworkListen: binds a local TCP socket and listens briefly to generate listen/bind telemetry.
- DNSQuery: resolves hostnames via the system resolver to generate DNS lookup activity.
- RawSocket: creates a raw socket (requires root) to generate privileged socket telemetry.

## User & Session Activity

- SessionActivity: collects current user IDs via libc and identifies the active console user via SystemConfiguration; uses libproc-based process presence checks for lock-related heuristics.

## Scheduled Task & Persistence

- CronTask: writes/removes a cron entry by editing the cron tab file directly and signals the cron daemon to reload.
- LaunchdPersistence: submits and removes a LaunchDaemon via ServiceManagement (SMJobSubmit/SMJobRemove) and performs a best-effort start via launchd XPC.
- LoginItemPersistence: adds and removes a session login item through LaunchServices shared file list APIs.

## User Account Activity

- UserAccountEvents: creates, modifies, and deletes a local user via OpenDirectory.framework APIs (system API path used by directory services). Home directory artifacts are created under `/tmp/edr_telem_userhomes` to avoid touching `/Users`.

## Access Activity

- RawDeviceAccess: attempts to open and read a raw disk device node to generate direct device access telemetry (typically requires root).
- ProcessAccess: attempts `task_for_pid` first (primary get-task telemetry surface), then performs a best-effort ptrace attach/detach attempt for additional process access coverage.

## Process Tampering Activity

- ProcessInjection: simulates a DYLD-based injection attempt by setting injection-related environment state and starting a child process; also attempts Mach task access via task_for_pid when available.

## System Extension & Driver Activity

- KextOperations: enumerates loaded kernel extensions via IOKit KextManager APIs and performs API-level kext load/unload attempts. On modern hardened macOS builds, load/unload usually fails and notify events may be limited.

## Code Signing & Trust Activity

- CodeSignTrust: validates signature state via Security.framework for a trusted system binary and a tampered copy, executes both samples to generate process telemetry with different trust outcomes, and reads XProtect metadata. Primary goal is validating signing/trust enrichment on common events.

## Privacy & TCC Activity

- TCCOperations: performs real TCC access checks for Screen Recording (CoreGraphics) and Accessibility (AX APIs), plus read-only queries against TCC databases when accessible.

## Script Activity

- ScriptExecution: creates a small Python script file and executes it via execve-style process replacement to generate script execution telemetry without using shells.

## Device Activity

- ExternalMedia: enumerates mounted volumes under the standard mount root to generate external media context (mount/unmount is not performed).

## Service Activity

- ServiceActivity: creates/modifies/deletes a LaunchDaemon by submitting/removing jobs via ServiceManagement (modify implemented as remove then re-submit); best-effort start uses launchd XPC.

## Not Yet Implemented

- Profile Added/Removed telemetry (`ES_EVENT_TYPE_NOTIFY_PROFILE_ADD` / `..._PROFILE_REMOVE`) is a recommended next addition. Installing/removing configuration profiles via system APIs is handled through private framework surfaces and is not yet part of this generator.
