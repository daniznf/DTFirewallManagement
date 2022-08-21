# Daniele's Tools Firewall Management
DTFirewallManagement <br />
A collection of scripts to manage your built in firewall <br />
Copyright (C) 2022 Daniznf

### Description
This collection is written to accomplish 2 main points:
- Monitor firewall events
- Update firewall rules following CSV rules file

#### Update-Rules
The update script can be run often (es: at boot), to avoid unwanted rules being applied, edited, or removed when you didn't want to.
A CSV must be passed to the script to let it know what rules must be updated. That CSV may be exported by using the export script. <br />
Rules existing only in CSV files will be added (and enabled). <br />
Rules existing only in Firewall will be disabled (never deleted). <br />
Rules existing in both CSV and Firewall will be updated as per CSV file.

#### Export-Rules
The export script is useful to export the CSV used by Update-Rule. You can freely edit this CSV to your needs.

#### Monitor-Events
The monitor script can be run when you want to see in realtime what your firewall is blocking.
Each time an application gets blocked by firewall it will be displayed **briefly** by this script.
After displaying some recent events, every new event will be displayed (follow).

### Install
To let monitor script work, in the group policy "Audit Filtering Platform Connection" the "Failure" property must be checked.
When firewall will block inbound or outbound communication, this will be logged in the system's Security log, and at the same time the monitor script will be able to retrieve it.

### Run
Monitor-events:
Right click on this script and chose "Run with Powershell" (double-clicking will not work) or launch this script from powershell with desired parameters, if any.

Export-Rules:
Launch this script from powershell with needed parameters.

Update-Rules:
Launch this script from powershell with needed parameters.

### Monitor-Events output example
```
4/6/2022 4:21:52 PM
Application: (10123) C:\users\daniznf\application\application.exe
Protocol:    UDP OUT
Source:      192.168.100.101 : 10123
Destination: 10.0.0.1        : 80

4/6/2022 4:32:18 PM
Application: (8012) C:\program files\program1\program1.exe
Protocol:    TCP OUT
Source:      192.168.100.101 : 20123
Destination: 10.0.0.2        : 443

4/6/2022 4:33:01 PM
Application: (9045) C:\program files\program2\program2.exe
Protocol:    TCP IN
Source:      10.0.0.3        : 30123
Destination: 192.168.100.101 : 80
```

### Monitor-Events in Compact mode
```
16:34:51  (9012) application1.exe UDP OUT
192.168.100.1: 40123  -> 10.0.0.4: 80

16:35:11  (8034) application2.exe TCP IN
10.0.0.4: 40123  -> 192.168.100.1 : 443
```

### More Help
```
Get-Help .\Monitor-Events.ps1
```

```
Get-Help .\Export-Rules.ps1
```

```
Get-Help .\Update-Rules.ps1
```
