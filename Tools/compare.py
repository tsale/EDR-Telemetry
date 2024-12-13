import json
import os
import re
from prettytable import PrettyTable

# File paths
EDRS_INFO_FILE = "EDR_telem.json"
README_FILE = "README.md"

# Scoring definitions
FEATURES_DICT_VALUED = {
    "Yes": 1, "No": 0, "Via EnablingTelemetry": 1, 
    "Partially": 0.5, "Via EventLogs": 0.5, 
    "Pending Response": 0
}
CATEGORIES_VALUED = {
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

# Global EDR scores dictionary
EDRS_LIST = {}


def generate_scores_table():
    """
    Generate a Markdown table containing EDR scores based on the data in EDR_telem.json.
    """
    current_directory = os.path.dirname(__file__)
    main_folder = os.path.dirname(current_directory)
    full_file_path = os.path.join(main_folder, EDRS_INFO_FILE)

    # Load JSON data
    with open(full_file_path, "r") as fd:
        edrs_info = json.load(fd)

    # Calculate scores for each EDR
    for category in edrs_info:
        sliced_items = list(category.items())[2:]
        subcategory = list(category.items())[1][1]
        for key, value in sliced_items:
            try:
                EDRS_LIST[key] += FEATURES_DICT_VALUED[value] * CATEGORIES_VALUED[subcategory]
            except KeyError:
                EDRS_LIST[key] = FEATURES_DICT_VALUED[value] * CATEGORIES_VALUED[subcategory]

    # Sort the dictionary by scores
    sorted_dict = dict(reversed(sorted(EDRS_LIST.items(), key=lambda item: item[1])))

    # Round scores to two decimal places
    rounded_dict = {k: round(v, 2) for k, v in sorted_dict.items()}

    # Create a Markdown-compatible table
    table_md = "| **No.** | **EDRs**              | **Score** |\n"
    table_md += "|---------|-----------------------|-----------|\n"

    for i, (k, v) in enumerate(rounded_dict.items(), start=1):
        table_md += f"| {i}       | {k}                 | {v}       |\n"

    return table_md


def update_readme(table_md):
    """
    Update the README.md file with the generated table, replacing the section
    between "### EDR Scores" and "## EDR Telemetry Table".
    """
    with open(README_FILE, "r") as file:
        readme_content = file.read()

    # Define the section markers
    start_marker = "### EDR Scores"
    end_marker = "## EDR Telemetry Table"

    # Use regex to replace the section
    pattern = re.compile(
        f"{re.escape(start_marker)}.*?{re.escape(end_marker)}", re.DOTALL
    )
    updated_content = pattern.sub(f"{start_marker}\n\n{table_md}\n\n{end_marker}", readme_content)

    # Write the updated content back to README.md
    with open(README_FILE, "w") as file:
        file.write(updated_content)


def main():
    """
    Main function to generate the EDR scores table and update the README.md file.
    """
    # Generate the scores table
    scores_table = generate_scores_table()

    # Update the README.md file
    update_readme(scores_table)

    print("README.md has been updated with the EDR scores table.")


if __name__ == '__main__':
    main()