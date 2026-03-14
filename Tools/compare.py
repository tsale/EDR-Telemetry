import json
import os
import argparse
from prettytable import PrettyTable

# Scoring definitions
FEATURES_DICT_VALUED = {
    "Yes": 1, "No": 0, "Via EnablingTelemetry": 1, 
    "Partially": 0.5, "Via EventLogs": 0.5, 
    "Pending Response": 0
}
WINDOWS_CATEGORIES_VALUED = {
    "Process Creation": 1,
    "Process Termination": 0.5,
    "Process Access": 1,
    "Image/Library Loaded": 1,
    "Remote Thread Creation": 1,
    "Process Tampering Activity": 1,
    "Process Call Stacks":1,
    "Win32 API Telemetry": 1,
    "File Creation": 1,
    "File Opened": 1,
    "File Deletion": 1,
    "File Modification": 1,
    "File Renaming": 0.7,
    "Local Account Creation": 1,
    "Local Account Modification": 1,
    "Local Account Deletion": 0.5,
    "Account Login": 0.7,
    "Account Logoff": 0.4,
    "TCP Connection": 1,
    "UDP Connection": 1,
    "URL": 1,
    "DNS Query": 1,
    "File Downloaded": 1,
    "MD5": 1,
    "SHA": 1,
    "JA3/JA3s": 1,
    "IMPHASH": 1,
    "Key/Value Creation": 1,
    "Key/Value Modification": 1,
    "Key/Value Deletion": 0.7,
    "Scheduled Task Creation": 0.7,
    "Scheduled Task Modification": 0.7,
    "Scheduled Task Deletion": 0.5,
    "Service Creation": 1,
    "Service Modification": 0.7,
    "Service Deletion": 0.6,
    "Driver Loaded": 1,
    "Driver Modification": 1,
    "Driver Unloaded": 1,
    "Virtual Disk Mount": 0.5,
    "USB Device Unmount": 0.7,
    "USB Device Mount": 1,
    "Group Policy Modification": 0.3,
    "Pipe Creation": 0.8,
    "Pipe Connection": 1,
    "Agent Start": 0.2,
    "Agent Stop": 0.8,
    "Agent Install": 0.2,
    "Agent Uninstall": 1,
    "Agent Keep-Alive": 0.2,
    "Agent Errors": 0.2,
    "WmiEventConsumerToFilter": 1,
    "WmiEventConsumer": 1,
    "WmiEventFilter": 1,
    "BIT JOBS Activity": 1,
    "Script-Block Activity": 1,
    "Volume Shadow Copy Deletion": 0.5
}

# Linux-specific categories
LINUX_CATEGORIES_VALUED = {
    "Process Creation": 1,
    "Process Termination": 0.5,
    "File Creation": 1,
    "File Modification": 1,
    "File Deletion": 1,
    "User Logon": 0.7,
    "User Logoff": 0.4,
    "Logon Failed": 1,
    "Script Content": 1,
    "Network Connection": 1,
    "Network Socket Listen": 1,
    "DNS Query": 1,
    "Scheduled Task": 0.7,
    "User Account Created": 1,
    "User Account Modified": 1,
    "User Account Deleted": 0.5,
    "Driver Load": 1,
    "Driver Modification": 1,
    "Image Load": 1,
    "eBPF Event": 1,
    "Raw Access Read": 1,
    "Process Access": 1,
    "Process Tampering": 1,
    "Service Creation": 1,
    "Service Modification": 0.7,
    "Service Deletion": 0.6,
    "Agent Start": 0.2,
    "Agent Stop": 0.8,
    "MD5": 1,
    "SHA": 1,
    "Fuzzy Hash": 1
}

# macOS-specific categories
MACOS_CATEGORIES_VALUED = {
    # Process Activity
    "Process Creation": 1.0,
    "Process Termination": 0.5,
    # File Activity
    "File Creation": 1.0,
    "File Modification": 1.0,
    "File Deletion": 0.7,
    "File Attribute Change": 0.5,
    "File Open/Access": 1.0,        # Critical gap: infostealers (AMOS/Poseidon) read Keychain/browser credential stores directly
    # User & Session Activity
    "User Logon": 0.7,
    "User Logoff": 0.4,
    "Logon Failed": 1.0,
    "Screen Lock": 0.2,
    "Screen Unlock": 0.2,
    "Privilege Escalation (sudo etc.)": 1.0,
    # Script Activity
    "Script Execution": 1.0,        # AppleScript/osascript is the #1 delivery mechanism for macOS infostealers
    "Script Content": 1.0,
    # Network Activity
    "Network Connection": 1.0,
    "Network Socket Listen": 1.0,
    "DNS Query": 1.0,
    # Scheduled Task & Persistence Activity
    "Scheduled Task Change (cron/at)": 0.7,
    "Launchd Item Created": 1.0,    # Primary macOS persistence mechanism
    "Launchd Item Modified": 0.8,
    "Launchd Item Deleted": 0.5,
    "LoginItem Created": 1.0,       # Second major persistence vector
    "LoginItem Deleted": 0.5,
    "Background Task Registration Change": 1.0,  # BTM (macOS 13+) — growing exploitation
    # User Account Activity
    "User Account Created": 1.0,
    "User Account Modified": 0.8,
    "User Account Deleted": 0.5,
    "Group Membership Modified": 0.8,
    # System Extension & Driver Activity
    "System Extension Installed": 1.0,
    "System Extension Loaded": 0.8,
    "System Extension Uninstalled": 0.5,
    "DriverKit Extension Loaded": 0.7,
    "Kernel Extension Loaded (legacy)": 0.5,
    # Code Signing & Trust Activity
    "Binary Signature Info Recorded": 0.5,
    "Unsigned Or Ad Hoc Binary Executed": 1.0,
    "Notarization Status Recorded": 0.3,
    "Quarantine Flag Set": 0.5,
    "Quarantine Flag Cleared": 1.0,  # Classic Gatekeeper bypass step
    "Gatekeeper Decision Logged": 0.8,
    "XProtect Detection Logged": 0.8,
    "XProtect Remediation Logged": 0.7,
    # TCC Activity
    "TCC Prompt Shown": 0.7,
    "TCC Decision (Allow)": 0.8,
    "TCC Decision (Deny)": 0.7,
    "TCC Policy Change": 1.0,       # Direct TCC DB manipulation = TCC bypass
    "TCC Access Check": 0.8,
    # Memory & Injection Activity
    "Raw Device Access": 0.8,
    "Process Access": 1.0,
    "Process Injection Or Tampering": 1.0,
    # External Media
    "External Media Mounted": 0.8,  # DMG-based delivery is the dominant macOS malware delivery method
    "External Media Unmounted": 0.2,
    # EDR SysOps
    "Agent Start": 0.1,
    "Agent Stop": 0.8,
    "Agent Protection Disabled Or Tamper Event": 1.0,
    # Hashing
    "MD5 Available": 0.5,
    "SHA-256 Available": 1.0,
    "Fuzzy Hash Available": 0.7,
    # Service Activity
    "Service Created": 0.8,
    "Service Modified": 0.6,
    "Service Deleted": 0.5,
    # Profile Activity
    "Profile Added": 0.8,           # MDM profile injection is a real enterprise attack vector (ES profile_add)
    "Profile Removed": 0.8,
}

def determine_categories(filename):
    """
    Determine which categories to use based on the filename.
    """
    filename_lower = filename.lower()
    if "macos" in filename_lower:
        return MACOS_CATEGORIES_VALUED
    if "linux" in filename_lower:
        return LINUX_CATEGORIES_VALUED
    return WINDOWS_CATEGORIES_VALUED

def parse_arguments():
    """
    Parse command line arguments
    """
    parser = argparse.ArgumentParser(description='Compare EDR telemetry data and generate scores.')
    parser.add_argument('-f', '--file', 
                      default="EDR_telem.json",
                      help='Path to the EDR telemetry JSON file (default: EDR_telem.json)')
    return parser.parse_args()

def display_results(scores_dict, input_file):
    """
    Display the results in the terminal using PrettyTable
    """
    input_file_lower = input_file.lower()
    if "macos" in input_file_lower:
        os_type = "macOS"
    elif "linux" in input_file_lower:
        os_type = "Linux"
    else:
        os_type = "Windows"
    table = PrettyTable()
    table.field_names = ["Rank", "EDR", "Score"]
    
    # Add rows to the table
    for i, (edr, score) in enumerate(scores_dict.items(), 1):
        table.add_row([i, edr, score])
    
    # Set table style
    table.align = "l"  # Left align text
    table.align["Score"] = "r"  # Right align numbers
    table.border = True
    table.hrules = True
    
    # Print results
    print(f"\n{os_type} EDR Telemetry Scores")
    print(f"Input file: {input_file}")
    print("\n" + str(table))

def generate_scores(input_file):
    """
    Generate scores based on the data in the input file.
    """
    current_directory = os.path.dirname(__file__)
    main_folder = os.path.dirname(current_directory)
    full_file_path = os.path.join(main_folder, input_file)

    # Load JSON data
    with open(full_file_path, "r") as fd:
        edrs_info = json.load(fd)

    # Determine which categories to use
    categories = determine_categories(input_file)

    # Calculate scores for each EDR
    edrs_list = {}
    for category in edrs_info:
        sliced_items = list(category.items())[2:]
        subcategory = list(category.items())[1][1]
        for key, value in sliced_items:
            category_value = categories.get(subcategory, 0)
            feature_value = FEATURES_DICT_VALUED.get(value, 0)
            edrs_list[key] = edrs_list.get(key, 0) + feature_value * category_value

    # Sort and round the scores
    return dict(sorted(
        ((k, round(v, 2)) for k, v in edrs_list.items()),
        key=lambda x: x[1],
        reverse=True
    ))

def main():
    """
    Main function to generate and display EDR scores.
    """
    args = parse_arguments()
    scores = generate_scores(args.file)
    display_results(scores, args.file)

if __name__ == '__main__':
    main()