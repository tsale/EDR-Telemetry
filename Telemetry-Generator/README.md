# Telemetry Generator

The telemetry generation tool is an early version (v0.1) software designed to help generate and test telemetry data. It utilizes the Invoke-AtomicRedTeam framework to map sub-categories to their corresponding atomic red team tests in order to generate the telemetry. This mapping information is stored in the config.json file, which the tool reads and executes the techniques accordingly.

Users have the flexibility to execute either one technique or all of the techniques by passing the -Name parameter (default=All). This makes it easy to generate telemetry and test it against the comparison table of the project, ensuring alignment and accuracy.

However, it is important to note that some sub-categories cannot be tested using this tool, such as USB Mount/Unmount and everything from the EDR-SysOps category. Despite these limitations, the telemetry generation tool serves as a valuable resource for generating and testing telemetry data in accordance with the Invoke-AtomicRedTeam framework.

## Feature Proofing

As the project expands and evolves, the telemetry generation tool will continue to improve and incorporate new features and capabilities. This ongoing development will ensure that the tool remains relevant and effective in generating and testing telemetry data in line with the Invoke-AtomicRedTeam framework and the project's goals.
