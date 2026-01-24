# macOS Telemetry Generator Guide

## Overview

The macOS Telemetry Generator is a tool created to generate controlled telemetry events for EDR testing on macOS systems. It performs system operations using direct syscalls and native framework API calls (ctypes) to produce known events that can be used to validate which telemetry an EDR actually captures.

This tool is part of the [EDR Telemetry Project](https://github.com/tsale/EDR-Telemetry) and follows the same methodology as the Windows and Linux telemetry generators.

## Requirements

| Requirement | Details |
|-------------|---------|
| Operating System | macOS 10.15 (Catalina) or later |
| Python Version | Python 3.8 or later |
| Privileges | Root required (run via sudo) |
| Dependencies | prettytable (optional, for formatted output) |

### Installing Dependencies

```bash
pip3 install prettytable
```

## Usage

### Basic Usage

Run all telemetry events:

```bash
sudo python3 macos_telem_gen.py
```

### Run Specific Events

Run only selected telemetry events:

```bash
sudo python3 macos_telem_gen.py ProcessCreation FileCreation NetworkConnection
```

### List Available Events

```bash
python3 macos_telem_gen.py --help
```

### Run with Root Privileges

This tool is intended to be run as root to generate the expected telemetry:

```bash
sudo python3 macos_telem_gen.py
```

Note: When running under `sudo`, user-session operations (LaunchAgents/Services) are executed as the invoking user (via setuid/setgid) to ensure they run in the correct per-user launchd domain.

## Telemetry Categories

The macOS Telemetry Generator covers the following categories based on the decided events as per PR [macOS EDR Categories and Sub Categories](https://github.com/tsale/EDR-Telemetry/pull/150):

### 1. Process Activity

| Event | Description | Syscall/API |
|-------|-------------|-------------|
| ProcessCreation | Creates child processes | fork(), posix_spawn() |
| ProcessTermination | Terminates processes with signals | kill(), signal() |
| PrivilegeEscalation | Attempts privilege transitions | seteuid(), setegid() |

### 2. File Activity

| Event | Description | Syscall/API |
|-------|-------------|-------------|
| FileCreation | Creates files | open() with O_CREAT |
| FileModification | Modifies file contents | write() |
| FileDeletion | Deletes files | unlink() |
| FileAttributeChange | Changes file permissions/ownership | chmod(), chown() |
| FileOpenAccess | Opens existing file read-only | open() + read() |
| ExtendedAttributes | Manipulates xattrs | setxattr(), getxattr() |

### 3. User & Session Activity

| Event | Description | Mechanism |
|-------|-------------|-----------|
| SessionActivity | Session/user context and lock heuristics | SystemConfiguration, libproc |

This category covers:
- Current user information via getuid(), getgid(), getlogin() syscalls
- Console user detection via SystemConfiguration framework
- Process presence checks via libproc (e.g., ScreenSaverEngine/loginwindow)

### 4. Network Activity

| Event | Description | Syscall/API |
|-------|-------------|-------------|
| NetworkConnection | Establishes outbound connections | socket(), connect() |
| NetworkListen | Creates listening sockets | bind(), listen() |
| DNSQuery | Performs DNS resolution | getaddrinfo() |
| RawSocket | Creates raw sockets (requires root) | socket(SOCK_RAW) |

### 5. Scheduled Task & Persistence Activity

| Event | Description | Mechanism |
|-------|-------------|-----------|
| CronTask | Creates/removes cron jobs | direct tab file writes + SIGHUP |
| LaunchdPersistence | Launchd job submit/remove (+ best-effort start) | ServiceManagement SMJobSubmit/SMJobRemove + launchd XPC start |
| LoginItemPersistence | Session login item add/remove | LaunchServices LSSharedFileList |

### 6. User Account Activity

| Event | Description | Tool/API |
|-------|-------------|----------|
| UserAccountEvents | Creates/modifies/deletes users | dslocal record plist writes |

### 7. System Extension & Driver Activity

| Event | Description | Mechanism |
|-------|-------------|-----------|
| KextOperations | Kernel extension enumeration | IOKit KextManager APIs |

### 8. Code Signing & Trust Activity

| Event | Description | Mechanism |
|-------|-------------|-----------|
| CodeSignTrust | Signature validity, quarantine, Gatekeeper, XProtect metadata | Security.framework, xattr, plist reads |

This category covers:
- Code signature verification via codesign
- Unsigned binary creation and detection
- Quarantine attribute manipulation via xattr
- Gatekeeper assessment via spctl
- XProtect status checking
- Notarization verification via stapler

### 9. Privacy & TCC Activity

| Event | Description | Framework |
|-------|-------------|-----------|
| TCCOperations | TCC access checks and database queries | CoreGraphics/AX APIs + TCC.db |

### 10. Access Activity

| Event | Description | Syscall/API |
|-------|-------------|-------------|
| RawDeviceAccess | Reads from raw devices | open(/dev/rdisk*) |
| ProcessAccess | Attempts process tracing | ptrace(), task_for_pid() |
| ProcessInjection | Demonstrates injection techniques | DYLD_INSERT_LIBRARIES |

### 11. Script Activity

| Event | Description | Mechanism |
|-------|-------------|-----------|
| ScriptExecution | Executes various script types | bash, python, osascript |

### 12. Device Activity

| Event | Description | Mechanism |
|-------|-------------|-----------|
| ExternalMedia | Detects mounted volumes | /Volumes |

### 13. Service Activity

| Event | Description | Mechanism |
|-------|-------------|-----------|
| ServiceActivity | Service creation, modification, deletion, start/stop | ServiceManagement SMJobSubmit/SMJobRemove + launchd XPC start |

This category covers:
- Service plist creation and management
- Service state changes (start/stop/enable/disable)
- Background Task Management (BTM) status
- Launchctl operations

## Architecture

The tool is organized into the following structure:

```
macOS/
├── macos_telem_gen.py              # Main telemetry generator script
├── MACOS_TELEMETRY_GENERATOR_GUIDE.md  # This documentation
├── requirements.txt                # Python dependencies
└── complex/                        # Advanced telemetry modules
    ├── __init__.py
    ├── process_injection.py        # Process injection techniques
    ├── persistence_launchd.py      # Launchd persistence
    ├── persistence_loginitem.py    # Login item persistence
    ├── user_account_manager.py     # User account management
    ├── kext_operations.py          # Kernel/system extensions
    ├── tcc_operations.py           # TCC/privacy operations
    ├── session_activity.py         # User session events
    ├── codesign_trust.py           # Code signing & trust
    ├── service_activity.py         # Service management
```

## Implementation Details

### Syscall-Based Approach

The tool prioritizes using direct syscalls and API calls over shell commands or executing binaries.

### Example: File Creation

Instead of using `touch` or shell redirection, the tool uses the `open()` syscall directly:

```python
# Using ctypes to call open() syscall
libc = ctypes.CDLL(ctypes.util.find_library('c'))
O_CREAT = 0x0200
O_WRONLY = 0x0001
fd = libc.open(path.encode('utf-8'), O_CREAT | O_WRONLY, 0o644)
```

### Example: Network Connection

The tool uses Python's socket module which wraps the underlying syscalls:

```python
# Creates socket() and connect() syscalls
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("8.8.8.8", 53))
```

### Example: Process Creation

Process creation uses the fork() syscall directly:

```python
# Direct fork() syscall
pid = os.fork()
if pid == 0:
    # Child process
    os._exit(0)
```

### macOS-Specific Considerations

| Feature | macOS Behavior |
|---------|----------------|
| SIP (System Integrity Protection) | Blocks many operations on system files |
| TCC (Transparency, Consent, Control) | Requires user consent for sensitive resources |
| Gatekeeper | May block unsigned code execution |
| Hardened Runtime | Restricts certain capabilities |
| Code Signing | Required for some system APIs |

## macOS Telemetry Sources

The tool generates events that can be captured by these macOS telemetry sources:

| Source | Description |
|--------|-------------|
| EndpointSecurity (ES) | Primary sensor feed for process, file, and security events |
| Unified Logging System (ULS) | Structured logging for OS and app context |
| TCC | Privacy protection framework for sensitive resources |
| NetworkExtension | Per-process network telemetry |
| SystemExtensions/DriverKit | Modern replacement for kernel extensions |
| OpenDirectory | Local and network account management |
| DiskArbitration | Disk and volume mount/unmount events |
| launchd/BTM | Background task and persistence management |

## Output

### Console Output

The tool provides detailed console output showing:
- Each event being executed
- Success/failure status
- Relevant details (PIDs, file paths, etc.)

### CSV Log

Results are logged to `macos_telemetry_log.csv` with columns:
- Timestamp
- Function name
- Status (Success/Failed/Error)
- Error message (if any)

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "Operation not permitted" | Run with sudo for privileged operations |
| "SIP is enabled" | Some operations require SIP to be disabled |
| TCC prompts appearing | Grant permissions or run in non-interactive mode |
| Import errors | Ensure all complex modules are in place |
| `module 'os' has no attribute 'setxattr'` | Use the current version of the generator (xattrs are performed via libc wrappers, not `os.*xattr`) |

### Launchd (SMJobSubmit) Errors

| Symptom | Cause | Fix |
|--------|-------|-----|
| `CFErrorDomainLaunchd error 2` for LaunchdPersistence/ServiceActivity | SMJobSubmit/SMJobRemove domain/launchd context issue | Run the generator under `sudo` (required). If it still fails, the OS may not support SMJobSubmit in this context (vendor hardening/OS variant). |

### FileOpenAccess Permission Errors

| Symptom | Cause | Fix |
|--------|-------|-----|
| `open() failed, errno: 13 (Permission denied)` under `/var/folders/...` | Running under `sudo` with inherited `TMPDIR` pointing to a per-user temp directory that root cannot use on some systems | The generator now uses `/tmp` for file telemetry artifacts. |

### Gatekeeper (SecAssessment) Traps

| Symptom | Cause | Behavior |
|--------|-------|----------|
| `Trace/BPT trap: 5` / `SIGTRAP` during `CodeSignTrust` | Some OS builds terminate on certain SecAssessment paths | The generator runs Gatekeeper assessment in a child process; if the child traps, the parent continues and still logs the event as executed. |

### Checking SIP Status

```bash
csrutil status
```

### Checking TCC Permissions

```bash
# List TCC database entries (requires FDA)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access"
```

## Security Considerations

This tool is designed for **generating macOS telemetry for EDR testing and validation**. Before using:

1. Obtain proper authorization
2. Ensure you have a backup
3. Understand the operations being performed

The tool creates and removes test files, users, and configurations. While it attempts to clean up after itself, manual verification is recommended.

## Contributing

Contributions are welcome! Please see the main [EDR Telemetry repository](https://github.com/tsale/EDR-Telemetry) for contribution guidelines.

## License

This project is licensed under the MIT License - see the LICENSE file in the main repository for details.