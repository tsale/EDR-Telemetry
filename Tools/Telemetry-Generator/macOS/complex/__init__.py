"""
macOS Telemetry Generator - Complex Modules

This package contains advanced telemetry generation modules for macOS EDR testing.
Each module focuses on a specific category of telemetry events.

Modules:
- process_injection: Process injection and tampering techniques
- persistence_launchd: Launchd-based persistence mechanisms
- persistence_loginitem: Login item persistence mechanisms
- user_account_manager: User and group account management
- kext_operations: Kernel and system extension operations
- tcc_operations: TCC (privacy) related operations
- session_activity: User session and authentication events
- codesign_trust: Code signing, Gatekeeper, and XProtect
- service_activity: Service/daemon management operations
"""

from .process_injection import process_injection_demo
from .persistence_launchd import launchd_persistence
from .persistence_loginitem import loginitem_persistence
from .user_account_manager import UserAccountManager
from .kext_operations import kext_operations
from .tcc_operations import tcc_operations
from .session_activity import session_activity_events
from .codesign_trust import codesign_trust_events
from .service_activity import service_activity_events

__all__ = [
    'process_injection_demo',
    'launchd_persistence',
    'loginitem_persistence',
    'UserAccountManager',
    'kext_operations',
    'tcc_operations',
    'session_activity_events',
    'codesign_trust_events',
    'service_activity_events',
]
