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
    "Script-Block Activity": 1
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
    "IMPHASH": 1
}

def determine_categories(filename):
    """
    Determine which categories to use based on the filename.
    """
    if "linux" in filename.lower():
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
    os_type = "Linux" if "linux" in input_file.lower() else "Windows"
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
            try:
                category_value = categories.get(subcategory, 0)
                edrs_list[key] = edrs_list.get(key, 0) + FEATURES_DICT_VALUED[value] * category_value
            except KeyError:
                category_value = categories.get(subcategory, 0)
                edrs_list[key] = FEATURES_DICT_VALUED[value] * category_value

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