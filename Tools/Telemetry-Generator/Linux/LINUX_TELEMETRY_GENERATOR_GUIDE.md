# Linux Telemetry Generator

## Overview

This script, `lnx_telem_gen.py`, is designed to generate various telemetry events for the EDR (Endpoint Detection and Response) telemetry project. The script performs a wide range of activities that are typically monitored by EDR solutions, such as file operations, network connections, process manipulation, and more. The goal is to help validate that the EDR solution is correctly capturing and reporting these events.

## Features

The script includes the following functionalities:

1. **File Operations**: Create, modify, and delete files.
2. **DNS Query**: Perform a DNS query.
3. **Process Termination**: Create and terminate a process.
4. **Image Load**: Load a shared library.
5. **Process Access**: Hijack a process and manipulate its memory and registers.
6. **Network Connections**: Establish TCP connections and create raw sockets.
7. **Service Start/Stop**: Start and stop a service using system calls.
8. **Raw Access Read**: Perform raw read access on a device.
9. **Driver Load**: Write, compile, and load a Linux kernel module.
10. **Process Tampering**: Tamper with the memory of a running process.
11. **Scheduled Task**: Create and remove scheduled tasks using cron.
12. **User Account Events**: Create, modify, and delete user accounts.
13. **Network Listening**: Create a listening socket for incoming TCP connections.

## Usage

To run the script, use the following command:

```bash
python3 lnx_telem_gen.py [Event1 Event2 ...]
```
If no events are specified, the script will run all available events. You can specify one or more events to run only those specific tests.

**Example**

```python
python3 lnx_telem_gen.py FileCreated DnsQuery NetworkConnect
```

This command will run the `FileCreated`, `DnsQuery`, and `NetworkConnect` events.

## Event List

- `FileCreated`
- `FileModified`
- `FileDelete`
- `DnsQuery`
- `ProcessTerminate`
- `ImageLoad`
- `ProcessAccess`
- `NetworkConnect`
- `ServiceStartStop`
- `RawAccessRead`
- `LoadDriver`
- `TamperProcess`
- `ScheduledTask`
- `UserAccountEvents`
- `NetworkListen`
- `NetworkRawSocket`

## Disclaimers

- **Best Effort**: This script is provided on a best-effort basis. If you do not see telemetry events for a specific category, please refer to the official documentation for your EDR vendor.
- **System Calls**: These tests are designed to avoid reliance on system binaries, which could allow the EDR to infer activity based on command line arguments or binaries executed on the host. Instead, this script uses system calls to perform the actions.

## Logging
The script logs the output of each function to a CSV file named function_output_log.csv. This file includes the function name, output, and any errors encountered during execution.

## Requirements
- Python 3.x
- Required Python packages: `dbus-python`, `libuser`, `ctypes`

## Installation
To install the required packages, run:

```bash
sudo apt-get install python3-dbus python3-libuser
```

## License
This project is licensed under the MIT License.