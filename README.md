# EDR Telemetry

This repo provides a list of _**telemetry features**_ from EDR products and other endpoint agents such as [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) broken down by category. The main motivation behind this project is to enable security practitioners to compare and evaluate the telemetry potential from those tools while encouraging EDR vendors to be more transparent about the telemetry features they do provide to their users and customers.

Besides compliance, investigations and forensics benefits, rich log telemetry empowers cyber defense teams to develop custom hunting, detection and analytics capabilities tailored to their needs.

Read details about this project in the initial release blog post [here](https://kostas-ts.medium.com/edr-telemetry-project-a-comprehensive-comparison-d5ed1745384b). 

## Telemetry Definition
There are many types of *telemetry* when it comes to Security Instrumentation. Here we focus on agents or sensors generating telemetry in the form of *log data*, regardless of the format (json, key-value, csv), as long as the data is automatically generated and transmitted or streamed in near real-time.

## FAQ & Contributions

Please check our [FAQ](https://github.com/tsale/EDR-Telemetry/wiki/FAQ) page to know more and feel free to get in contact in case you cannot find an answer there.

In case you ware willing to contribute, please check the [Contributions](https://github.com/tsale/EDR-Telemetry/wiki#contribution-guidelines) page.

>**Disclaimer**\
The telemetry of the EDR products below could improve with time. The `last_updated` field is the last time the data sources have been updated. This might NOT always be up to date with the current telemetry capabilities of each product.
>

Telemetry Comparison Table
-----------------------------------

>**Disclaimer**\
The data below do not represent the capability of each of the EDR products to detect or prevent a threat. This is ONLY a comparison regarding the available telemetry for each product. Some products, such as Elastic EDR, make additional telemetry available in free or paid modules. Add-on modules, as well as signals, will not be taken into consideration for this project. Please read more about this on our FAQ page [here](https://github.com/tsale/EDR-Telemetry/wiki/FAQ#7-what-is-the-scope-of-the-telemetry-comparison-table-for-edr-products).

<br>

| CSV Values 	| JSON Values               	| Description
|-------	|-----------------------	|-----------------------
| 🟩     	| Yes           	        | Implemented
| 🟥     	| No       	                | Not Implemented
| 🟧     	| Partially	                | Partially Implemented
| ❓     	| Pending                	| Pending Response
| 🪵     	| Via EventLogs           	| Via Windows EventLogs
| 🎚️     	| Via EnablingTelemetry         	| Additional telemetry that can be enabled easily as part of the EDR product but is not on by default.
<br>

**Last Updated:** Thu December 07 2023\
**Google SpreadSheet Table:** [Link](https://docs.google.com/spreadsheets/d/1ZMFrD6F6tvPtf_8McC-kWrNBBec_6Si3NW6AoWf3Kbg/edit?usp=sharing) \
**References to Documentation for each EDR product:** [Link](https://github.com/tsale/EDR-Telemetry/wiki#product-documentation-references)
| **Telemetry Feature Category** | **Sub-Category**            | **Carbon Black** | **CrowdStrike** | **Cybereason** | **ESET Inspect** | **Elastic** | **LimaCharlie** | **MDE** | **Qualys** | **Sentinel One** | **Sysmon** | **Trellix** | **Trend Micro** | **WatchGuard** |
|:------------------------------:|:---------------------------:|:----------------:|:---------------:|:--------------:|:----------------:|:-----------:|:---------------:|:-------:|:----------:|:----------------:|:----------:|:-----------:|:---------------:|:--------------:|
| **Process Activity**           | Process Creation            | 🟩               | 🟩              | 🟩             | 🟩               | 🟩          | 🟩              | 🟩      | 🟩         | 🟩               | 🟩         | 🟩          | 🟩              | 🟩             |
| ****                           | Process Termination         | 🟧               | 🟩              | 🟩             | 🟩               | 🟩          | 🟩              | 🟩      | 🟩         | 🟥               | 🟩         | 🟥          | 🎚️             | 🟥             |
| ****                           | Process Access              | 🟩               | 🟩              | 🟩             | 🟧               | 🟩          | 🟩              | 🟩      | 🟥         | 🟩               | 🟩         | 🟩          | 🟩              | 🟥             |
| ****                           | Image/Library Loaded        | 🟩               | 🟩              | 🟩             | 🟩               | 🟩          | 🟩              | 🟩      | 🟩         | 🟩               | 🟩         | 🟩          | 🟩              | 🟩             |
| ****                           | Remote Thread Creation      | 🟩               | 🟩              | 🟩             | 🟩               | 🟩          | 🟩              | 🟩      | 🟥         | 🟩               | 🟩         | 🟩          | 🟩              | 🟩             |
| ****                           | Process Tampering Activity  | 🟧               | 🟩              | ❓              | 🟥               | 🟩          | 🟩              | 🟩      | 🟥         | 🟧               | 🟩         | 🟩          | 🟩              | 🟥             |
| **File Manipulation**          | File Creation               | 🟩               | 🟩              | 🟩             | 🟧               | 🟩          | 🟩              | 🟩      | 🟩         | 🟩               | 🟩         | 🟩          | 🟩              | 🟧             |
| ****                           | File Opened                 | 🟩               | 🟧              | 🟥             | 🟥               | 🟩          | 🟥              | 🟥      | 🟥         | 🟥               | 🟥         | 🟩          | 🟧              | 🟧             |
| ****                           | File Deletion               | 🟩               | 🟩              | 🟩             | 🟩               | 🟩          | 🟩              | 🟩      | 🟩         | 🟩               | 🟩         | 🟩          | 🟥              | 🟥             |
| ****                           | File Modification           | 🟩               | 🟩              | 🟥             | 🟩               | 🟩          | 🟩              | 🟩      | 🟥         | 🟩               | 🟥         | 🟩          | 🟩              | 🟥             |
| ****                           | File Renaming               | 🟩               | 🟩              | 🟩             | 🟩               | 🟩          | 🟥              | 🟩      | 🟩         | 🟩               | 🟥         | 🟩          | 🟥              | 🟧             |
| **User Account Activity**      | Local Account Creation      | 🟥               | 🟩              | 🟥             | 🟩               | 🟥          | 🟥              | 🟩      | 🟥         | 🟥               | 🟥         | 🟩          | 🟥              | 🟥             |
| ****                           | Local Account Modification  | 🟥               | 🟧              | 🟥             | 🟩               | 🟥          | 🟥              | 🟩      | 🟥         | 🟥               | 🟥         | 🟩          | 🟥              | 🟥             |
| ****                           | Local Account Deletion      | 🟥               | 🟩              | 🟥             | 🟩               | 🟥          | 🟥              | 🟩      | 🟥         | 🟥               | 🟥         | 🟩          | 🟥              | 🟥             |
| ****                           | Account Login               | 🪵               | 🟩              | 🟩             | 🟩               | 🟩          | 🟧              | 🟩      | 🟥         | 🟩               | 🟥         | 🟩          | 🪵              | 🟩             |
| ****                           | Account Logoff              | 🪵               | 🟩              | 🟩             | 🟩               | 🟩          | 🟥              | 🟥      | 🟥         | 🟥               | 🟥         | 🟩          | 🪵              | 🟩             |
| **Network Activity**           | TCP Connection              | 🟩               | 🟩              | 🟩             | 🟩               | 🟩          | 🟩              | 🟩      | 🟩         | 🟩               | 🟩         | 🟩          | 🟩              | 🟩             |
| ****                           | UDP Connection              | 🟩               | 🟩              | 🟩             | 🟥               | 🟩          | 🟩              | 🟩      | 🟩         | 🟥               | 🟩         | 🟩          | 🟩              | 🟩             |
| ****                           | URL                         | 🟥               | 🟩              | 🟥             | 🟩               | 🟧          | 🟧              | 🟩      | 🟩         | 🎚️              | 🟥         | 🟩          | 🟥              | 🟧             |
| ****                           | DNS Query                   | 🟩               | 🟩              | 🟩             | 🟩               | 🟩          | 🟩              | 🟩      | 🟥         | 🟩               | 🟩         | 🟩          | 🟩              | 🟩             |
| ****                           | File Downloaded             | 🟥               | 🟩              | 🟧             | 🟧               | 🟥          | 🟧              | 🟩      | 🟥         | 🟥               | 🟥         | 🟥          | 🟩              | 🟩             |
| **Hash Algorithms**            | MD5                         | 🟩               | 🟩              | 🟩             | 🟩               | 🟩          | 🟩              | 🟩      | 🟩         | 🟩               | 🟩         | 🟩          | 🟩              | 🟩             |
| ****                           | SHA                         | 🟩               | 🟩              | 🟩             | 🟩               | 🟩          | 🟩              | 🟩      | 🟩         | 🟩               | 🟩         | 🟩          | 🟩              | 🟥             |
| ****                           | IMPHASH                     | 🟥               | 🟥              | 🟥             | 🟥               | 🟧          | 🟥              | 🟥      | 🟥         | 🟥               | 🟩         | 🟥          | 🟥              | 🟥             |
| **Registry Activity**          | Key/Value Creation          | 🟩               | 🟧              | 🟧             | 🟩               | 🟩          | 🟩              | 🟩      | 🟩         | 🟩               | 🟩         | 🟩          | 🟩              | 🟩             |
| ****                           | Key/Value Modification      | 🟩               | 🟧              | 🟧             | 🟩               | 🟩          | 🟩              | 🟩      | 🟥         | 🟩               | 🟩         | 🟩          | 🟩              | 🟩             |
| ****                           | Key/Value Deletion          | 🟩               | 🟥              | 🟧             | 🟩               | 🟩          | 🟩              | 🟩      | 🟩         | 🟩               | 🟩         | 🟩          | 🟩              | 🟩             |
| **Schedule Task Activity**     | Scheduled Task Creation     | 🟥               | 🟩              | 🟩             | 🟥               | 🟥          | 🟥              | 🟩      | 🟥         | 🟩               | 🟥         | 🟥          | 🪵              | 🟥             |
| ****                           | Scheduled Task Modification | 🟥               | 🟩              | 🟩             | 🟥               | 🟥          | 🟥              | 🟩      | 🟥         | 🟩               | 🟥         | 🟩          | 🟥              | 🟥             |
| ****                           | Scheduled Task Deletion     | 🟥               | 🟩              | 🟥             | 🟥               | 🟥          | 🟥              | 🟩      | 🟥         | 🟩               | 🟥         | 🟥          | 🟥              | 🟥             |
| **Service Activity**           | Service Creation            | 🟧               | 🟩              | 🟩             | 🟥               | 🟥          | 🟩              | 🪵      | 🟥         | 🟥               | 🟥         | 🟥          | 🟥              | 🟧             |
| ****                           | Service Modification        | 🟥               | 🟧              | 🟥             | 🟥               | 🟥          | 🟩              | 🟥      | 🟥         | 🟥               | 🟥         | 🟩          | 🟥              | 🟧             |
| ****                           | Service Deletion            | 🟥               | 🟥              | 🟥             | 🟥               | 🟥          | ❓               | 🟥      | 🟥         | 🟥               | 🟥         | 🟥          | 🟥              | 🟥             |
| **Driver/Module Activity**     | Driver Loaded               | 🟥               | 🟩              | 🟩             | 🟩               | 🟩          | 🟥              | 🟩      | 🟥         | 🟩               | 🟩         | 🟥          | 🟥              | 🟥             |
| ****                           | Driver Modification         | 🟥               | 🟩              | 🟥             | 🟥               | 🟥          | 🟩              | 🟥      | 🟥         | 🟥               | 🟥         | 🟥          | 🟥              | 🟥             |
| ****                           | Driver Unloaded             | 🟥               | 🟥              | 🟥             | 🟥               | 🟥          | 🟥              | 🟥      | 🟥         | 🟥               | 🟥         | 🟥          | 🟥              | 🟥             |
| **Device Operations**          | Virtual Disk Mount          | 🟥               | 🟩              | 🟥             | 🟥               | 🟥          | 🟩              | 🟥      | 🟥         | 🟥               | 🟥         | 🟥          | 🟥              | 🟩             |
| ****                           | USB Device Unmount          | 🟥               | 🟩              | 🟩             | 🟥               | 🟥          | 🟥              | 🟩      | 🟥         | 🟥               | 🟥         | 🟥          | 🟥              | 🟩             |
| ****                           | USB Device Mount            | 🟧               | 🟩              | 🟩             | 🟥               | 🟥          | 🟥              | 🟩      | 🟥         | 🎚️              | 🟥         | 🟥          | 🟥              | 🟩             |
| **Other Relevant Events**      | Group Policy Modification   | 🟥               | 🟥              | 🟥             | 🟥               | 🟥          | 🟥              | 🟩      | 🟥         | 🟥               | 🟥         | 🟥          | 🟥              | 🟥             |
| **Named Pipe Activity**        | Pipe Creation               | 🟧               | 🟩              | 🟥             | 🟩               | 🟥          | 🟩              | 🟩      | 🟥         | 🎚️              | 🟩         | 🟥          | 🟥              | 🟥             |
| ****                           | Pipe Connection             | 🟥               | 🟩              | 🟥             | 🟥               | 🟥          | 🟩              | 🟩      | 🟥         | 🎚️              | 🟩         | 🟩          | 🟥              | 🟥             |
| **EDR SysOps**                 | Agent Start                 | 🟥               | 🟩              | 🟩             | 🟥               | 🟥          | 🟩              | 🟥      | 🟩         | 🟩               | 🟩         | ❓           | 🟥              | 🟥             |
| ****                           | Agent Stop                  | 🟥               | 🟩              | 🟩             | 🟥               | 🟩          | 🟩              | 🟥      | 🟩         | 🟩               | 🟩         | ❓           | 🟥              | 🟥             |
| ****                           | Agent Install               | 🟥               | 🟥              | 🟩             | 🟩               | 🟥          | 🟩              | 🟥      | 🟩         | 🟩               | 🟥         | 🟩          | 🟥              | 🟩             |
| ****                           | Agent Uninstall             | 🟥               | 🟩              | 🟩             | 🟩               | 🟩          | 🟥              | 🟥      | 🟥         | 🟩               | 🟥         | 🟩          | 🟥              | 🟩             |
| ****                           | Agent Keep-Alive            | 🟥               | 🟩              | 🟩             | 🟩               | 🟥          | 🟩              | 🟥      | 🟩         | 🟩               | 🟥         | ❓           | 🟥              | 🟥             |
| ****                           | Agent Errors                | 🟥               | 🟩              | 🟥             | 🟩               | 🟩          | 🟩              | 🟩      | 🟩         | 🟩               | 🟩         | ❓           | 🟥              | 🟥             |
| **WMI Activity**               | WmiEventConsumerToFilter    | 🟥               | 🟩              | 🟩             | 🟩               | 🟥          | 🟥              | 🟩      | 🟥         | 🟥               | 🟩         | 🟩          | 🪵              | 🟩             |
| ****                           | WmiEventConsumer            | 🟥               | 🟥              | 🟩             | 🟩               | 🟥          | 🟥              | 🟩      | 🟥         | 🟥               | 🟩         | 🟩          | 🪵              | 🟩             |
| ****                           | WmiEventFilter              | 🟥               | 🟥              | 🟩             | 🟩               | 🟥          | 🟥              | 🟩      | 🟥         | 🟥               | 🟩         | 🟩          | 🪵              | 🟩             |
| **BIT JOBS Activity**          | BIT JOBS Activity           | 🟥               | 🟩              | 🟥             | 🟥               | 🟥          | 🟥              | 🟥      | 🟥         | 🟥               | 🟥         | 🟩          | 🟥              | 🟥             |
| **PowerShell Activity**        | Script-Block Activity       | 🟩               | 🟩              | 🟥             | 🟩               | 🟥          | 🟥              | 🟩      | 🟥         | 🟩               | 🟥         | 🟩          | 🟥              | 🟥             |









## Current Primary Maintainers
Kostas - [@kostastsale](https://twitter.com/Kostastsale)\
Alex - [@ateixei](https://twitter.com/ateixei)
