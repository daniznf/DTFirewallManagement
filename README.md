# Daniele's Tools Firewall Management
DTFirewallManagement <br/>
Exports to CSV and updates from CSV firewall rules. <br/>
Copyright (C) 2022-2023 Daniznf

### Description
This module exposes 2 commands:
- Export-FWRules: exports firewall rules to CSV or to shell
- Update-FWRules: updates firewall rules with values of CSV file.

#### Export-FWRules
Parses firewall rules finding properties like program, addresses, ports, etc., and exports them to a CSV file
that can be used to update firewall using the command Update-FWRules (see below), or just prints them in shell.
You can freely edit this CSV, editing, removing, or adding rules.<br>
Any field that contains the ignore tag will be ignored. This tag is written in the first line of CSV file.

#### Update-FWRules
The update script can be run often (e.g.: at boot), to avoid unwanted rules from being applied, edited,
or removed by other softwares when you didn't want to.
A CSV must be passed to the script to let it know what rules must be enabled, disabled or updated.
That CSV may be exported by using the above mentioned Export-FWRules. <br/>
Rules existing only in CSV files will be added (and enabled). <br/>
Rules existing only in firewall will be disabled (never deleted). <br/>
Rules existing in both CSV and firewall will be updated as per CSV file
(when using FastMode they will only be enabled, disabled or added).


### More Help
```
Get-Help Export-FWRules
```

```
Get-Help Update-FWRules
```

### Requisites
This module requires administrator privileges.

### Install
Run DTInstallModule.ps1 in DTFirewallManagement directory (https://github.com/daniznf/DTInstallModule), or copy module directory into one of directories in $env:PSModulePath.

### Uninstall
Delete DTFirewallManagement directory from the one you chose in $env:PSModulePath.