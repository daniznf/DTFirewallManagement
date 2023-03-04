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

$MinVersion = [System.Version]::new("0.20.0")

function Get-FilteredNetFirewallRules {
    param (
        [string]
        $DisplayName,

        [string]
        $Group,

        [string]
        $DisplayGroup,

        [ValidateSet("Allow", "Block")]
        [string]
        $Action,

        [ValidateSet("True", "False")]
        [string]
        $Enabled,

        [ValidateSet("Inbound", "Outbound")]
        [string]
        $Direction
    )

    $NFRules = Get-NetFirewallRule

    # Where-Object is more flexible than Get-NetFirewallRule's built-in filters. It permits:
    # - Combining DisplayName with other filters
    # - Filtering using -match
    if ($DisplayName) { $NFRules = $NFRules | Where-Object { $_.DisplayName -match $DisplayName } }
    if ($Group) { $NFRules = $NFRules | Where-Object { $_.Group -match $Group } }
    if ($DisplayGroup) { $NFRules = $NFRules | Where-Object { $_.DisplayGroup -match $DisplayGroup } }
    if ($Action) { $NFRules = $NFRules | Where-Object { $_.Action -eq $Action } }
    if ($Enabled) { $NFRules = $NFRules | Where-Object { $_.Enabled -eq $Enabled } }
    if ($Direction) { $NFRules = $NFRules | Where-Object { $_.Direction -eq $Direction } }

    return $NFRules

    <#
    .SYNOPSIS
        Gets all NetFirewallRules that correspond to filters.

    .DESCRIPTION
        Filters firewall rules with passed filters.

    .PARAMETER DisplayName
        Gets only rules with a DisplayName that matches this value.

    .PARAMETER Group
        Exports only rules with a Group that matches this value.

    .PARAMETER DisplayGroup
        Exports only rules with a DisplayGroup that matches this value.
        This parameter is only used to filter exported rules, and actually depends on $Group parameter of each rule.

    .PARAMETER Action
        Exports only rules with this Action value.

    .PARAMETER Enabled
        Exports only rules with this Enabled value.

    .PARAMETER Direction
        Exports only rules with this Direction value.

    .OUTPUTS
        An array of CimInstance objects.
    #>
}

function Export-FWRules {
    param (
        [string]
        $PathCSV,

        [string]
        $DisplayName,

        [string]
        $Group,

        [string]
        $DisplayGroup,

        [ValidateSet("Allow", "Block")]
        [string]
        $Action,

        [ValidateSet("True", "False")]
        [string]
        $Enabled,

        [ValidateSet("Inbound", "Outbound")]
        [string]
        $Direction
    )

    if ($PathCSV -and (Test-Path $PathCSV))
    {
        $Overwrite = Read-Host -Prompt "File exists. Overwrite it? [y/n]"

        if (($Overwrite -eq "y") -or ($Overwrite -eq "yes")) { Remove-Item $PathCSV -ErrorAction Stop}
        else { throw "Rules have not been written to File!" }
    }

    $GFParams = @{}

    if ($DisplayName) { $GFParams.Add("DisplayName", $DisplayName) }
    if ($Group) { $GFParams.Add("Group", $Group) }
    if ($DisplayGroup) { $GFParams.Add("DisplayGroup", $DisplayGroup) }
    if ($Action) { $GFParams.Add("Action", $Action) }
    if ($Enabled) { $GFParams.Add("Enabled", $Enabled) }
    if ($Direction) { $GFParams.Add("Direction", $Direction) }

    $NFRules = Get-FilteredNetFirewallRules @GFParams

    # If only one rule is found, $NFRules is not an array.
    if ($NFRules -isnot [System.Array]) { $NFRules = @($NFRules) }

    $NFRulesCount = $NFRules.Count

    if ($PathCSV)
    {
        # If module is not found, an exception will be thrown but function will continue.
        $ModuleVersion = (Test-ModuleManifest "$script:PSScriptRoot\DTFirewallManagement.psd1").Version

        $OutRules = New-Object System.Collections.ArrayList

        # Create a special rule to be consumed only by Update-FWRules, to avoid updating rules that were not exported.
        $DefaultRule = [FWRule]::new()
        $DefaultRule.ID = "DTFMDefaultRule"
        $DefaultRule.DisplayName = $DisplayName
        $DefaultRule.Group = $Group
        $DefaultRule.Description = "Parameters used when exporting rules, do not edit this line!! Use ""{0}"" , without quotes, to ignore any field." -f [FWRule]::IgnoreTag
        $DefaultRule.Program = "DTFirewallManagement"
        $DefaultRule.Enabled = $Enabled
        $DefaultRule.Direction = $Direction
        $DefaultRule.Action = $Action
        $DefaultRule.Profile = ""
        $DefaultRule.Protocol =  ""
        $DefaultRule.LocalAddress =  $ModuleVersion
        $DefaultRule.LocalPort =  ""
        $DefaultRule.RemoteAddress =  ""
        $DefaultRule.RemotePort =  ""

        $OutRules.Add($DefaultRule) > $null
    }

    for ($i = 0; $i -lt $NFRulesCount; $i++)
    {
        $NFRule = $NFRules[$i]

        Write-Progress -Activity ("Parsing rule " + $NFRule.DisplayName) -PercentComplete ($i / $NFRulesCount * 100)

        $FWRule = Get-FWRule -NFRule $NFRule
        if ($PathCSV)
        {
            $OutRules.Add($FWRule) > $null
        }
        else
        {
            $FWRule
        }
    }

    if ($PathCSV)
    {
        $OutRules | Export-Csv $PathCSV -NoTypeInformation
        Write-Host "Exported" $PathCSV
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

    .PARAMETER DisplayName
        Exports only rules with a DisplayName that matches this value.

    .PARAMETER Group
        Exports only rules with a Group that matches this value.

    .PARAMETER DisplayGroup
        Exports only rules with a DisplayGroup that matches this value.
        This parameter is only used to filter exported rules, and actually depends on $Group parameter of each rule.

    .PARAMETER Action
        Exports only rules with this Action value.

    .PARAMETER Enabled
        Exports only rules with this Enabled value.

    .PARAMETER Direction
        Exports only rules with this Direction value.

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
        Exports to user's desktop all firewall rules in Rules.csv

    .EXAMPLE
        Export-FWRules -PathCSV "$env:USERPROFILE\Desktop\Filtered_Rules.csv" -Enabled True -Action Allow -Profile Private -Direction Inbound
        Exports into Filtered_Rules.csv all enabled rules that allow traffic in private profile in inbound direction.
    #>
}

function Find-Rule {
    param (
        [Parameter(Mandatory)]
        [Array]
        $Rules,

        [string]
        $ID = "",

        [string]
        $DisplayName = "",

        [string]
        $Group = "",

        [string]
        $Description = "",

        [string]
        $Enabled = "",

        [string]
        $RProfile = "",

        [string]
        $Direction = "",

        [string]
        $Action = ""
    )

    $RuleToReturn = $null
    for ($i = 0; $i -lt $Rules.Length; $i++)
    {
        $Rule = $Rules[$i]
        if ((($ID -eq "") -or ($ID -eq $Rule.ID) -or ($ID -eq $Rule.InstanceID)) -and
            (($DisplayName -eq "") -or ($DisplayName -eq $Rule.DisplayName)) -and
            (($Group -eq "") -or ($Group -eq $Rule.Group)) -and
            (($Description -eq "") -or ($Description -eq $Rule.Description)) -and
            (($Enabled -eq "") -or ($Enabled -eq $Rule.Enabled)) -and
            (($RProfile -eq "") -or ($RProfile -eq $Rule.Profile)) -and
            (($Direction -eq "") -or ($Direction -eq $Rule.Direction)) -and
            (($Action -eq "") -or ($Action -eq $Rule.Action)))
        {
            $RuleToReturn = $Rule
            break
        }
    }
    return $RuleToReturn

    <#
    .SYNOPSIS
        Finds a rule with parameters equal to given ones.

    .DESCRIPTION
        Rule can be searched passing any combination of parameters.

    .PARAMETER Rules
        An array of rules of type CimInstance or FWRule.

    .PARAMETER ID
        ID that has to be equal to the ID of the rule to be found.

    .PARAMETER DisplayName
        DisplayName that has to be equal to the DisplayName of the rule to be found.

    .PARAMETER Group
        Group that has to be equal to the Group of the rule to be found.

    .PARAMETER Description
        Description that has to be equal to the Description of the rule to be found.

    .PARAMETER Enabled
        Enabled value that has to be equal to the Enabled value of the rule to be found.

    .PARAMETER RProfile
        Profile value that has to be equal to the Profile value of the rule to be found.

    .PARAMETER Direction
        Direction value that has to be equal to the Direction value of the rule to be found.

    .PARAMETER Action
        Action value that has to be equal to the Action value of the rule to be found.

    .OUTPUTS
        The first rule corresponding to search parameters, if found, or $null if not found.
        The type of this rule matches the array passed in Rules parameter.

    .EXAMPLE
        Find-Rule -Rules (Get-NetFirewallRule) -ID "MyRuleID"

    .EXAMPLE
        Find-Rule -Rules (Get-FWRules) -ID "MyRuleID"
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

    $ForwardingParams = @{}
    if ($WhatIf) { $ForwardingParams.Add("WhatIf", $WhatIf) }
    if ($Silent) { $ForwardingParams.Add("Silent", $Silent) }

    if (-not (Test-Path $PathCSV)) { throw [System.IO.FileNotFoundException]::new("Cannot find Rules CSV file!") }

    if (-not $Silent) { Write-Host "Reading $PathCSV..." }
    $CSVRules = Import-Csv $PathCSV

    # Use default rule written in csv to know which filters were used during export, then update rules with the same filters.
    $DefaultRule = $CSVRules[0]
    if ($DefaultRule.ID -eq "DTFMDefaultRule")
    {
        $CSVVersion = $null
        if ([System.Version]::TryParse($DefaultRule.LocalAddress, [ref] $CSVVersion))
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
        $Action = $DefaultRule.Action
        $Enabled = $DefaultRule.Enabled
        $Direction = $DefaultRule.Direction
    }
    else { throw "Cannot find default rule in CSV file.
                    Please run Export-FWRules to have a compatible CSV file." }

    $GFParams = @{}

    if ($DisplayName) { $GFParams.Add("DisplayName", $DisplayName) }
    if ($Group) { $GFParams.Add("Group", $Group) }
    if ($DisplayGroup) { $GFParams.Add("DisplayGroup", $DisplayGroup) }
    if ($Action) { $GFParams.Add("Action", $Action) }
    if ($Enabled) { $GFParams.Add("Enabled", $Enabled) }
    if ($Direction) { $GFParams.Add("Direction", $Direction) }

    if (-not $Silent)
    {
        Write-Host "Reading current firewall rules" -NoNewline
        if ($DisplayName -or $Action -or $Enabled -or $Direction -or $Group)
        {
            Write-Host " with filters: "  -NoNewline
            if ($DisplayName) { Write-Host "DisplayName" $DisplayName -NoNewline }
            if ($Action)
            {
                if ($DisplayName) { Write-Host ", " -NoNewline }
                Write-Host "Action" $Action -NoNewline
            }
            if ($Enabled)
            {
                if ($DisplayName -or $Action) { Write-Host ", " -NoNewline }
                Write-Host "Enabled" $Enabled -NoNewline
            }
            if ($Direction)
            {
                if ($DisplayName -or $Action -or $Enabled) { Write-Host ", " -NoNewline }
                Write-Host "Direction" $Direction -NoNewline
            }
            if ($Group)
            {
                if ($DisplayName -or $Action -or $Enabled -or $Direction) { Write-Host ", " -NoNewline }
                Write-Host "Group" $Group -NoNewline
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

        if (-not $Silent) { Write-Progress -Activity ("Parsing rule " + $CurrentRule.DisplayName) -PercentComplete ($i / $FilteredRules.Count * 100) }

        $CSVRule = Find-Rule -Rules $CSVRules -ID $CurrentRule.InstanceID
        if (-not $CSVRule)
        {
            # If $CSVRule was not found, check if $CurrentRule has a corresponding CSVRule with ignored ID.
            $CSVRule = Find-Rule -Rules $CSVRules -ID ([FWRule]::IgnoreTag) `
                        -DisplayName $CurrentRule.DisplayName `
                        -Group $CurrentRule.Group `
                        -Description $CurrentRule.Description `
                        -Enabled $CurrentRule.Enabled `
                        -RProfile $CurrentRule.Profile `
                        -Direction $CurrentRule.Direction `
                        -Action $CurrentRule.Action

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

    # Update all rules with the same ID, or create new ones.
    for ($i = 1; $i -lt $CSVRules.Count; $i++)
    {
        # $i = 0 is DefaultRule
        $CSVRule = $CSVRules[$i]

        if (-not $CSVRule.ID) { continue }

        if (-not $Silent) { Write-Progress -Activity ("Parsing rule " + $CSVRule.DisplayName) -PercentComplete ($i / $CSVRules.Count * 100) }

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

                $CurrentRule = Find-Rule -Rules $FirewallRules -ID $CSVRule.ID

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


Export-ModuleMember -Function Export-FWRules, Update-FWRules
