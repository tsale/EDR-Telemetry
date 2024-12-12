import json
import os
from prettytable import PrettyTable


EDRS_INFO_FILE = "EDR_telem.json"
FEATURES_DICT_VALUED = {"Yes" : 1, "No" : 0, "Via EnablingTelemetry" : 1, "Partially" : 0.5, "Via EventLogs" : 0.5, "Pending Response" : 0}
CATEGORIES_VALUED = {"Process Creation":1,
"Process Termination":0.5,
"Process Access":1,
"Image/Library Loaded":1,
"Remote Thread Creation":1,
"Process Tampering Activity":1,
"File Creation":1,
"File Opened":1,
"File Deletion":1,
"File Modification":1,
"File Renaming":0.7,
"Local Account Creation":1,
"Local Account Modification":1,
"Local Account Deletion":0.5,
"Account Login":0.7,
"Account Logoff":0.4,
"TCP Connection":1,
"UDP Connection":1,
"URL":1,
"DNS Query":1,
"File Downloaded":1,
"MD5":1,
"SHA":1,
"IMPHASH":1,
"Key/Value Creation":1,
"Key/Value Modification":1,
"Key/Value Deletion":0.7,
"Scheduled Task Creation":0.7,
"Scheduled Task Modification":0.7,
"Scheduled Task Deletion":0.5,
"Service Creation":1,
"Service Modification":0.7,
"Service Deletion":0.6,
"Driver Loaded":1,
"Driver Modification":1,
"Driver Unloaded":1,
"Virtual Disk Mount":0.5,
"USB Device Unmount":0.7,
"USB Device Mount":1,
"Group Policy Modification":0.3,
"Pipe Creation":0.8,
"Pipe Connection":1,
"Agent Start":0.2,
"Agent Stop":0.8,
"Agent Install":0.2,
"Agent Uninstall":1,
"Agent Keep-Alive":0.2,
"Agent Errors":0.2,
"WmiEventConsumerToFilter":1,
"WmiEventConsumer":1,
"WmiEventFilter":1,
"BIT JOBS Activity":1,
"Script-Block Activity":1 }
EDRS_LIST = {}


def main():
    current_directory = os.path.dirname(__file__)
    main_folder = os.path.dirname(current_directory)
    full_file_path = os.path.join(main_folder, EDRS_INFO_FILE)

    with open(full_file_path, "r") as fd:
        edrs_info = json.load(fd)

    for category in edrs_info:
        sliced_items = list(category.items())[2:]
        subcategory = list(category.items())[1][1]
        for key, value in sliced_items:
            try:
                EDRS_LIST[key] += FEATURES_DICT_VALUED[value] * CATEGORIES_VALUED[subcategory]
            except KeyError:
                EDRS_LIST[key] = FEATURES_DICT_VALUED[value] * CATEGORIES_VALUED[subcategory]

    # Sort the dictionary by values numerically
    sorted_dict = dict(reversed(sorted(EDRS_LIST.items(), key=lambda item: item[1])))
    
    # Round the values to two decimal places
    rounded_dict = {k: round(v, 2) for k, v in sorted_dict.items()}
    #print(json.dumps(rounded_dict, indent=2))

    # Create a table
    table = PrettyTable()

    # Add columns
    table.field_names = ["No.", "EDRS", "Score"]
    for i, (k, v) in enumerate(rounded_dict.items(), start=1):
        table.add_row([i, k, v])

    print(table)


if __name__ == '__main__':
    main()