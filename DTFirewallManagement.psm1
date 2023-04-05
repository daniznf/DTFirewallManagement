<#
    Daniele's Tools Firewall Management
    Copyright (C) 2022-2023 Daniznf

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    https://github.com/daniznf/DTFirewallManagement
#>

#Requires -RunAsAdministrator
using module ".\Modules\FWRule.psm1"

function Get-FilteredNetFirewallRules {
    param (
        [string]
        $ID,

        [string]
        $DisplayName,

        [string]
        $Group,

        [string]
        $DisplayGroup,

        [ValidateSet("True", "False")]
        [string]
        $Enabled,

        [ValidateSet("Any", "Domain", "Private", "Public")]
        [string]
        $RuleProfile,

        [ValidateSet("Inbound", "Outbound")]
        [string]
        $Direction,

        [ValidateSet("Allow", "Block")]
        [string]
        $Action
    )

    $NFRules = Get-NetFirewallRule

    # Where-Object is more flexible than Get-NetFirewallRule's built-in filters. It permits:
    # - Combining DisplayName with other filters
    # - Filtering using -match
    if ($ID) { $NFRules = $NFRules | Where-Object { $_.ID -eq $ID } }
    if ($DisplayName) { $NFRules = $NFRules | Where-Object { $_.DisplayName -match $DisplayName } }
    if ($Group) { $NFRules = $NFRules | Where-Object { $_.Group -match $Group } }
    if ($DisplayGroup) { $NFRules = $NFRules | Where-Object { $_.DisplayGroup -match $DisplayGroup } }
    if ($Enabled) { $NFRules = $NFRules | Where-Object { $_.Enabled -eq $Enabled } }
    if ($RuleProfile) { $NFRules = $NFRules | Where-Object { $_.Profile -eq $RuleProfile } }
    if ($Direction) { $NFRules = $NFRules | Where-Object { $_.Direction -eq $Direction } }
    if ($Action) { $NFRules = $NFRules | Where-Object { $_.Action -eq $Action } }

    return $NFRules

    <#
    .SYNOPSIS
        Gets all NetFirewallRules that correspond to filters, directly from firewall.

    .DESCRIPTION
        Filters firewall rules with passed filters.

    .PARAMETER ID
        Gets only the rule with this ID.

    .PARAMETER DisplayName
        Gets only rules with a DisplayName that matches this value.

    .PARAMETER Group
        Exports only rules with a Group that matches this value.

    .PARAMETER DisplayGroup
        Exports only rules with a DisplayGroup that matches this value.
        This parameter is only used to filter exported rules, and actually depends on $Group parameter of each rule.

    .PARAMETER Enabled
        Exports only rules with this Enabled value.

    .PARAMETER RuleProfile
        Exports only rules with this RuleProfile value.

    .PARAMETER Direction
        Exports only rules with this Direction value.

    .PARAMETER Action
        Exports only rules with this Action value.

    .OUTPUTS
        An array of CimInstance objects.
    #>
}

function Export-FWRules {
    param (
        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [string]
        $PathCSV,

        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [string]
        $ID,

        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [string]
        $DisplayName,

        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [string]
        $Group,

        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [string]
        $DisplayGroup,

        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [string]
        $Program,

        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [ValidateSet("True", "False")]
        [string]
        $Enabled,

        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [ValidateSet("Any", "Domain", "Private", "Public")]
        [string]
        $RuleProfile,

        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [ValidateSet("Inbound", "Outbound")]
        [string]
        $Direction,

        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [ValidateSet("Allow", "Block")]
        [string]
        $Action,

        [Parameter(Mandatory, ParameterSetName="ProtocolName")]
        [ValidateSet("TCP", "UDP", "ICMPv4", "ICMPv6")]
        [string]
        $ProtocolName,

        [Parameter(Mandatory, ParameterSetName="ProtocolNumber")]
        [ValidateRange(0, 255)]
        [int]
        $ProtocolNumber,

        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [string]
        $LocalAddress,

        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [string]
        $LocalPort,

        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [string]
        $RemoteAddress,

        [Parameter(ParameterSetName="Default")]
        [Parameter(ParameterSetName="ProtocolName")]
        [Parameter(ParameterSetName="ProtocolNumber")]
        [string]
        $RemotePort
    )

    $ModuleVersion = Read-Version
    if (-not $Silent) { Write-Host "DTFirewallManagement version $ModuleVersion" }

    $Protocol = ""
    if ($PSCmdlet.ParameterSetName -eq "ProtocolNumber") { $Protocol = $ProtocolNumber.ToString() }
    else { $Protocol = $ProtocolName }

    if ($PathCSV -and (Test-Path $PathCSV))
    {
        $Overwrite = Read-Host -Prompt "File exists. Overwrite it? [y/n]"

        if (($Overwrite -eq "y") -or ($Overwrite -eq "yes")) { Remove-Item $PathCSV -ErrorAction Stop}
        else { throw "Rules have not been written to File!" }
    }

    $GFParams = @{}
    if ($ID) { $GFParams.Add("ID", $ID) }
    if ($DisplayName) { $GFParams.Add("DisplayName", $DisplayName) }
    if ($Group) { $GFParams.Add("Group", $Group) }
    if ($DisplayGroup) { $GFParams.Add("DisplayGroup", $DisplayGroup) }
    if ($Enabled) { $GFParams.Add("Enabled", $Enabled) }
    if ($RuleProfile) { $GFParams.Add("RuleProfile", $RuleProfile) }
    if ($Direction) { $GFParams.Add("Direction", $Direction) }
    if ($Action) { $GFParams.Add("Action", $Action) }

    $TRMParams = @{}
    if ($Program) { $TRMParams.Add("Program", $Program) }
    if ($Protocol) { $TRMParams.Add("Protocol", $Protocol) }
    if ($LocalAddress) { $TRMParams.Add("LocalAddress", $LocalAddress) }
    if ($LocalPort) { $TRMParams.Add("LocalPort", $LocalPort) }
    if ($RemoteAddress) { $TRMParams.Add("RemoteAddress", $RemoteAddress) }
    if ($RemotePort) { $TRMParams.Add("RemotePort", $RemotePort) }

    $NFRules = Get-FilteredNetFirewallRules @GFParams

    # If only one rule is found, $NFRules is not an array.
    if ($NFRules -isnot [System.Array]) { $NFRules = @($NFRules) }

    $NFRulesCount = $NFRules.Count

    if ($PathCSV)
    {
        $OutRules = New-Object System.Collections.ArrayList

        # Create a special rule to be consumed only by Update-FWRules, to avoid updating rules that were not exported.
        $DefaultRule = [FWRule]::new()
        $DefaultRule.ID = "DTFMDefaultRule_v" + $ModuleVersion
        $DefaultRule.DisplayName = $DisplayName
        $DefaultRule.Group = $Group
        $DefaultRule.Program = $Program
        $DefaultRule.Enabled = $Enabled
        $DefaultRule.Profile = $RuleProfile
        $DefaultRule.Direction = $Direction
        $DefaultRule.Action = $Action
        $DefaultRule.Protocol =  $Protocol
        $DefaultRule.LocalAddress =  $LocalAddress
        $DefaultRule.LocalPort =  $LocalPort
        $DefaultRule.RemoteAddress =  $RemoteAddress
        $DefaultRule.RemotePort =  $RemotePort
        $DefaultRule.Description = "Parameters used when exporting rules, do not edit this line!! Use ""{0}"" , without quotes, to ignore any other field." -f [FWRule]::IgnoreTag
        $OutRules.Add($DefaultRule) > $null
    }

    for ($i = 0; $i -lt $NFRulesCount; $i++)
    {
        $NFRule = $NFRules[$i]

        Write-Progress -Activity "Parsing firewall rules" -PercentComplete ($i / $NFRulesCount * 100) -CurrentOperation $NFRule.DisplayName

        $FWRule = Get-FWRule -NFRule $NFRule

        if (Test-RuleMatch -FWRule $FWRule @TRMParams)
        {
            if ($PathCSV)
            {
                $OutRules.Add($FWRule) > $null
            }
            else
            {
                $FWRule
            }
        }
        # else FWRule does not meet filters requirements
    }

    if ($PathCSV)
    {
        $OutRules | Export-Csv -Path $PathCSV -NoTypeInformation
        Write-Host "Exported $PathCSV"
    }

    <#
    .SYNOPSIS
        Exports firewall rules to CSV, or prints them in shell.

    .DESCRIPTION
        Parses firewall rules finding properties like program, addresses, ports, etc., and exports them to
        a CSV file that can be used to update Firewall using the command Update-FWRules, or just prints them here.

    .PARAMETER PathCSV
        Complete path of CSV file where to write firewall rules.
        If not passed, rules will just be printed out in stdout.

    .PARAMETER ID
        Exports only the rule with this ID.

    .PARAMETER DisplayName
        Exports only rules with a DisplayName that matches this value.

    .PARAMETER Group
        Exports only rules with a Group that matches this value.

    .PARAMETER DisplayGroup
        Exports only rules with a DisplayGroup that matches this value.
        This parameter is only used to filter exported rules, and actually depends on $Group parameter of each rule.

    .PARAMETER Program
        Exports only rules with a Program that matches this value.

    .PARAMETER Enabled
        Exports only rules with this Enabled value.

    .PARAMETER RuleProfile
        Exports only rules with this RuleProfile value.

    .PARAMETER Direction
        Exports only rules with this Direction value.

    .PARAMETER Action
        Exports only rules with this Action value.

    .PARAMETER ProtocolName
        Exports only rules with this ProtocolName value.

    .PARAMETER ProtocolNumber
        Exports only rules with this ProtocolNumber value.

    .PARAMETER LocalAddress
        Exports only rules with this LocalAddress value.

    .PARAMETER LocalPort
        Exports only rules with this LocalPort value.

    .PARAMETER RemoteAddress
        Exports only rules with this RemoteAddress value.

    .PARAMETER RemotePort
        Exports only rules with this RemotePort value.

    .OUTPUTS
        An array of FWRule objects if no PathCSV is passed, otherwise nothing: all rules are written to file.

    .EXAMPLE
        Export-FWRules
        Displays all firewall rules in this shell

    .EXAMPLE
        Export-FWRules -DisplayName test -Action Allow
        Displays all firewall rules with action Allow with a DisplayName that contains "test"

    .EXAMPLE
        Export-FWRules -PathCSV "$env:USERPROFILE\Desktop\Rules.csv"
        Exports to user's desktop all firewall rules

    .EXAMPLE
        Export-FWRules -PathCSV "$env:USERPROFILE\Desktop\Filtered_Rules.csv" -Enabled True -Action Allow -Profile Private -Direction Inbound
        Exports into Filtered_Rules.csv all enabled rules that allow traffic in private profile in inbound direction.
    #>
}

function Find-Rule {
    param (
        [Parameter(Mandatory, ParameterSetName="CimRules")]
        [Array]
        $CimRules,

        [Parameter(Mandatory, ParameterSetName="FWRules")]
        [Array]
        $FWRules,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $ID,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $DisplayName,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $Group,

        [Parameter(ParameterSetName="FWRules")]
        [string]
        $Program,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $Enabled,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $RProfile,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $Direction,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $Action,

        [Parameter(ParameterSetName="FWRules")]
        [string]
        $Protocol,

        [Parameter(ParameterSetName="FWRules")]
        [string]
        $LocalAddress,

        [Parameter(ParameterSetName="FWRules")]
        [string]
        $LocalPort,

        [Parameter(ParameterSetName="FWRules")]
        [string]
        $RemoteAddress,

        [Parameter(ParameterSetName="FWRules")]
        [string]
        $RemotePort
    )

    $Rules = ""
    if ($PSCmdlet.ParameterSetName -eq "CimRules") { $Rules = $CimRules}
    else { $Rules = $FWRules }

    for ($i = 0; $i -lt $Rules.Length; $i++)
    {
        $Rule = $Rules[$i]

        if ((($ID -eq "") -or ($ID -eq $Rule.ID) -or ($ID -eq $Rule.InstanceID)) -and
            (($DisplayName -eq "") -or ($DisplayName -eq $Rule.DisplayName)) -and
            (($Group -eq "") -or ($Group -eq $Rule.Group)) -and
            (($Enabled -eq "") -or ($Enabled -eq $Rule.Enabled)) -and
            (($RProfile -eq "") -or ($RProfile -eq $Rule.Profile)) -and
            (($Direction -eq "") -or ($Direction -eq $Rule.Direction)) -and
            (($Action -eq "") -or ($Action -eq $Rule.Action)))
        {
            if ($Rule -is [FWRule])
            {
                if ((($Program -eq "") -or ($Program -eq $Rule.Program)) -and
                (($Protocol -eq "") -or ($Protocol -eq $Rule.Protocol)) -and
                (($LocalAddress -eq "") -or ($LocalAddress -eq $Rule.LocalAddress)) -and
                (($LocalPort -eq "") -or ($LocalPort -eq $Rule.LocalPort)) -and
                (($RemoteAddress -eq "") -or ($RemoteAddress -eq $Rule.RemoteAddress)) -and
                (($RemotePort -eq "") -or ($RemotePort -eq $Rule.RemotePort)))
                {
                    return $Rule
                }
            }
            else
            {
                return $Rule
            }
        }
    }

    <#
    .SYNOPSIS
        Finds a rule with parameters equal to given ones, in an array of rules.

    .DESCRIPTION
        Rule can be searched passing any combination of parameters.

    .PARAMETER CimRules
        An array of rules of type CimInstance.

    .PARAMETER FWRules
        An array of rules of type FWRule.

    .PARAMETER ID
        ID that has to be equal to the ID of the rule to be found.

    .PARAMETER DisplayName
        DisplayName that has to be equal to the DisplayName of the rule to be found.

    .PARAMETER Group
        Group that has to be equal to the Group of the rule to be found.

    .PARAMETER Program
        Program that has to be equal to the Program of the rule to be found.

    .PARAMETER Enabled
        Enabled value that has to be equal to the Enabled value of the rule to be found.

    .PARAMETER RProfile
        Profile value that has to be equal to the Profile value of the rule to be found.

    .PARAMETER Direction
        Direction value that has to be equal to the Direction value of the rule to be found.

    .PARAMETER Action
        Action value that has to be equal to the Action value of the rule to be found.

    .PARAMETER Protocol
        Protocol value that has to be equal to the Protocol value of the rule to be found.

    .PARAMETER LocalAddress
        LocalAddress value that has to be equal to the LocalAddress value of the rule to be found.

    .PARAMETER LocalPort
        LocalPort value that has to be equal to the LocalPort value of the rule to be found.

    .PARAMETER RemoteAddress
        RemoteAddress value that has to be equal to the RemoteAddress value of the rule to be found.

    .PARAMETER RemotePort
        RemotePort value that has to be equal to the RemotePort value of the rule to be found.

    .OUTPUTS
        The first rule corresponding to search parameters, if found, or $null if not found.
        The type of this rule matches the array passed in CimRules or FWRules.

    .EXAMPLE
        Find-Rule -CimRules (Get-NetFirewallRule) -ID "MyRuleID"

    .EXAMPLE
        Find-Rule -FWRules (Get-FWRules) -ID "MyRuleID"
    #>
}

function Update-FWRules
{
    param (
        [Parameter(Mandatory)]
        [string]
        $PathCSV,

        [Alias("DryRun")]
        [switch]
        $WhatIf,

        [switch]
        $Silent,

        [switch]
        $FastMode
    )

    $MinVersion = [System.Version]::new("0.24.2")
    $ModuleVersion = Read-Version
    if (-not $Silent) { Write-Host "DTFirewallManagement version $ModuleVersion" }

    $ForwardingParams = @{}
    if ($WhatIf) { $ForwardingParams.Add("WhatIf", $WhatIf) }
    if ($Silent) { $ForwardingParams.Add("Silent", $Silent) }

    if (-not (Test-Path $PathCSV)) { throw [System.IO.FileNotFoundException]::new("Cannot find Rules CSV file!") }

    if (-not $Silent) { Write-Host "Reading $PathCSV..." }
    $CSVRules = Import-Csv $PathCSV
    if ($null -eq $CSVRules)
    {
        throw [System.IO.InvalidDataException]::new("File is not valid. Please run Export-FWRules to have a compatible CSV file.")
    }

    $DefaultRule = $CSVRules[0]
    if ($null -eq $DefaultRule)
    {
        throw [System.IO.InvalidDataException]::new("File is not valid. Please run Export-FWRules to have a compatible CSV file.")
    }

    $Rule0ID = Get-Member -InputObject $DefaultRule -MemberType Properties | Where-Object -Property Name -EQ "ID"
    if ($null -eq $Rule0ID)
    {
        throw [System.IO.InvalidDataException]::new("File is not valid. Please run Export-FWRules to have a compatible CSV file.")
    }

    # Use default rule written in csv to know which filters were used during export, then update rules with the same filters.
    $DefaultID = $DefaultRule.ID
    if ($DefaultID.Contains("DTFMDefaultRule_v"))
    {
        $CSVVersion = $null
        $sVersion = $DefaultID.Substring($DefaultID.IndexOf("_v") + 2)
        if ([System.Version]::TryParse($sVersion, [ref] $CSVVersion))
        {
            if ($CSVVersion -lt $MinVersion)
            {
                throw "CSV File version is $CSVVersion, but at least $MinVersion is required.
                        Please run Export-FWRules to have a compatible CSV file."
            }
        }
        else
        {
            throw [System.Data.VersionNotFoundException]::new("Cannot read version from $PathCSV.
                    Please run Export-FWRules to have a compatible CSV file.")
        }

        $DisplayName = $DefaultRule.DisplayName
        $Group = $DefaultRule.Group
        $Program = $DefaultRule.Program
        $Enabled = $DefaultRule.Enabled
        $RProfile = $DefaultRule.Profile
        $Direction = $DefaultRule.Direction
        $Action = $DefaultRule.Action
        $Protocol = $DefaultRule.Protocol
        $LocalAddress = $DefaultRule.LocalAddress
        $LocalPort = $DefaultRule.LocalPort
        $RemoteAddress = $DefaultRule.RemoteAddress
        $RemotePort = $DefaultRule.RemotePort
    }
    else { throw "Cannot find default rule in CSV file.
                    Please run Export-FWRules to have a compatible CSV file." }

    $GFParams = @{}
    if ($DisplayName) { $GFParams.Add("DisplayName", $DisplayName) }
    if ($Group) { $GFParams.Add("Group", $Group) }
    if ($Enabled) { $GFParams.Add("Enabled", $Enabled) }
    if ($RProfile) { $GFParams.Add("RuleProfile", $RProfile) }
    if ($Direction) { $GFParams.Add("Direction", $Direction) }
    if ($Action) { $GFParams.Add("Action", $Action) }

    $TRMParams = @{}
    if ($Program) { $TRMParams.Add("Program", $Program) }
    if ($Protocol) { $TRMParams.Add("Protocol", $Protocol) }
    if ($LocalAddress) { $TRMParams.Add("LocalAddress", $LocalAddress) }
    if ($LocalPort) { $TRMParams.Add("LocalPort", $LocalPort) }
    if ($RemoteAddress) { $TRMParams.Add("RemoteAddress", $RemoteAddress) }
    if ($RemotePort) { $TRMParams.Add("RemotePort", $RemotePort) }

    if (-not $Silent)
    {
        Write-Host "Reading current firewall rules" -NoNewline

        if (($GFParams.Count -gt 0) -or ($TRMParams.Count -gt 0))
        {
            $separator = ""
            Write-Host " with filters: "  -NoNewline
            foreach ($Key in $GFParams.Keys)
            {
                Write-Host -NoNewline ($separator + $Key + " = " + $GFParams[$Key])
                $separator = ", "
            }
            foreach ($Key in $TRMParams.Keys)
            {
                Write-Host -NoNewline ($separator + $Key + " = " + $TRMParams[$Key])
                $separator = ", "
            }
        }

        Write-Host "..."
    }

    # Get all current firewall rules.
    $FirewallRules = Get-FilteredNetFirewallRules

    # Filter firewall rules with CSV filters.
    $FilteredRules = Get-FilteredNetFirewallRules @GFParams

    # If only one rule is found, $FilteredRules is not an array.
    if ($FilteredRules -isnot [System.Array]) { $FilteredRules = @($FilteredRules) }

    # Disable all firewall rules that are not present in CSV.
    for ($i = 0; $i -lt $FilteredRules.Count; $i++)
    {
        $CurrentRule = $FilteredRules[$i]

        if (-not $Silent) { Write-Progress -Activity "Checking if firewall rules are present in CSV" -PercentComplete ($i / $FilteredRules.Count * 100) -CurrentOperation $CurrentRule.DisplayName }

        $CSVRule = Find-Rule -FWRules $CSVRules -ID $CurrentRule.InstanceID
        if (-not $CSVRule)
        {
            # If rules were filtered by an attribute not included in CimInstance, FWRule is necessary.
            $CurrentFWRule = Get-FWRule -NFRule $CurrentRule

            if (Test-RuleMatch -FWRule $CurrentFWRule @TRMParams)
            {
                # If $CSVRule was not found, check if $CurrentRule has a corresponding CSVRule with ignored ID.
                $CSVRule = Find-Rule -FWRules $CSVRules[1..$CSVRules.Length] -ID ([FWRule]::IgnoreTag) `
                            -DisplayName $CurrentFWRule.DisplayName `
                            -Group $CurrentFWRule.Group `
                            -Program $CurrentFWRule.Program `
                            -Enabled $CurrentFWRule.Enabled `
                            -RProfile $CurrentFWRule.Profile `
                            -Direction $CurrentFWRule.Direction `
                            -Action $CurrentFWRule.Action `
                            -Protocol $CurrentFWRule.Protocol `
                            -LocalAddress $CurrentFWRule.LocalAddress `
                            -LocalPort $CurrentFWRule.LocalPort `
                            -RemoteAddress $CurrentFWRule.RemoteAddress `
                            -RemotePort $CurrentFWRule.RemotePort

                if ($CSVRule)
                {
                    if (-not $Silent) { Write-Host "Ignoring" $CurrentRule.DisplayName }
                }
                else
                {
                    Update-Attribute -AttributeName "Enabled" -SourceAttribute "False" -ComparingCimRule $CurrentRule @ForwardingParams
                }
            }
        }
    }

    # Update all rules with corresponding ID, or create new ones.
    for ($i = 1; $i -lt $CSVRules.Count; $i++)
    {
        # $i = 0 is DefaultRule
        $CSVRule = $CSVRules[$i]

        if (-not $CSVRule.ID) { continue }

        if (-not $Silent) { Write-Progress -Activity "Checking if CSV rules are present in firewall" -PercentComplete ($i / $CSVRules.Count * 100) -CurrentOperation $CSVRule.DisplayName }

        # Do not search for ignored IDs.
        if ($CSVRule.ID -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent) { Write-Host "Ignoring" $CSVRule.DisplayName }
        }
        else
        {
            if ($FastMode)
            {
                # FastMode compares $CSVRules with $FirewallRules, which is an array that comes directly from firewall using Get-NetFirewallRule.
                # It is faster than using Get-FWRule(s) but several properties are missing from each rule, so it is ok to enable or disable rules.

                $CurrentRule = Find-Rule -CimRules $FirewallRules -ID $CSVRule.ID

                # $CurrentRule is a CimInstance object.
                if ($CurrentRule)
                {
                    Update-Attribute -AttributeName "Enabled" -SourceAttribute $CSVRule.Enabled -ComparingCimRule $CurrentRule @ForwardingParams
                }
            }
            else
            {
                # Regular mode calls Get-FWRule for each rule of CSV, it's slower than Get-NetFirewallRule but all properties are filled in and can be compared.
                $CurrentRule = Get-FWRule -ID $CSVRule.ID

                # $CurrentRule is a FWRule object.
                if ($CurrentRule)
                {
                    Update-FWRule -SourceRule $CSVRule -ComparingRule $CurrentRule @ForwardingParams
                }
            }

            if (-not $CurrentRule)
            {
                Add-FWRule -NewRule $CSVRule @ForwardingParams
            }
        }
    }


    <#
    .SYNOPSIS
        Updates firewall rules with corresponding values in CSV file.

    .DESCRIPTION
        Rules present only in CSV files will be added (and enabled).
        Rules present only in firewall will be disabled (never deleted).
        Rules present in both CSV and firewall will be updated as per CSV file.
        Please use Export-FWRules, first, to export the CSV files with rules of your firewall.

    .PARAMETER PathCSV
        Complete path of CSV file containing rules to check.

    .PARAMETER WhatIf
        Do not actually modify firewall, only show what would happen.

    .PARAMETER Silent
        Do not write anything but errors and new added rules.

    .PARAMETER FastMode
        Only enable or disable rules.

    .EXAMPLE
        Update-FWRules -PathCSV "$env:USERPROFILE\Desktop\Rules.csv"
        Reads rules Rules.csv, in user's desktop, and updates firewall consequently.

    .EXAMPLE
        Update-FWRules -PathCSV "$env:USERPROFILE\Desktop\Rules.csv" -WhatIf
        Only simulate changes in firewall, but do not actually modify it.

    .EXAMPLE
        Update-FWRules -PathCSV "$env:USERPROFILE\Desktop\Rules.csv" -FastMode
        Fast check and update only Enabled values.
    #>
}

function Read-Version {
    return (Test-ModuleManifest "$script:PSScriptRoot\DTFirewallManagement.psd1").Version
}


Export-ModuleMember -Function Export-FWRules, Update-FWRules
