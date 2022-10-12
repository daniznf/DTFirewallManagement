<#
    Daniele's Tools Firewall Management
    Copyright (C) 2022 Daniznf

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

function Export-FWRules {
    param (
        [string]
        $PathCSV,

        [string]
        [ValidateSet("Allow", "Block")]
        $Action,

        [string]
        [ValidateSet("True", "False")]
        $Enabled,

        [string]
        [ValidateSet("Inbound", "Outbound")]
        $Direction
    )

    $GFR = @{}
    if ($Action) { $GFR.Add("Action", $Action) }
    if ($Enabled) { $GFR.Add("Enabled", $Enabled) }
    if ($Direction) { $GFR.Add("Direction", $Direction) }

    # Create a special rule to be consumed only by Update-FWRules, to avoid updating rules that were not exported
    $DefaultRule = [FWRule]::new()
    $DefaultRule.ID = "DefaultRule"
    $DefaultRule.DisplayName = "Default Rule"
    $DefaultRule.Description = "Parameters used when calling exporting rules, do not edit this line!! Use ""{0}"" , without quotes, to ignore any field." -f [FWRule]::IgnoreTag
    $DefaultRule.Program = "DTFirewallManagement"
    $DefaultRule.Enabled = $Enabled
    $DefaultRule.Direction = $Direction
    $DefaultRule.Action = $Action
    $DefaultRule.Profile = ""
    $DefaultRule.LocalAddress =  ""
    $DefaultRule.RemoteAddress =  ""
    $DefaultRule.Protocol =  ""
    $DefaultRule.LocalPort =  ""
    $DefaultRule.RemotePort =  ""

    $RuleList = New-Object System.Collections.ArrayList
    $RuleList.Add($DefaultRule) > $null

    if ($PathCSV)
    {
        if (Test-Path $PathCSV)
        {
            $overwrite = Read-Host -Prompt "File exists. Overwrite it? [y/n]"

            if (($overwrite -eq "y") -or ($overwrite -eq "yes"))
            {
                Remove-Item $PathCSV
            }
            else
            {
                throw "Rules have not been written to File!"
            }
        }
    }

    $Rules = Get-FWRules @GFR
    $RuleList.AddRange($Rules)

    if ($PathCSV)
    {
        $RuleList | Export-Csv $PathCSV -NoTypeInformation
        Write-Host "Exported" $PathCSV
    }
    else
    {
        $RuleList
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

    .PARAMETER Action
        Read only rules with this Action value

    .PARAMETER Enabled
        Read only rules with this Enabled value

    .PARAMETER Direction
        Read only rules with this Direction value

    .PARAMETER Version
        Show script version

    .EXAMPLE
        Export-FWRules
        Displays matching rules in this shell

    .EXAMPLE
        Export-FWRules -PathCSV "$env:USERPROFILE\Desktop\Rules.csv"
        Exports to user's desktop all firewall rules in Rules.csv

    .EXAMPLE
        Export-FWRules -PathCSV "$env:USERPROFILE\Desktop\Filtered_Rules.csv" -Enabled True -Action Allow -Profile Private -Direction Inbound
        Exports into Filtered_Rules.csv all enabled rules that allow traffic in Private profile in inbound direction.
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
        Finds a rule that matches given parameters.

    .DESCRIPTION
        Rule can be searched passing any combination of parameters.

    .PARAMETER Rules
        An array of rules of type Ciminstance or FWRule.

    .PARAMETER ID
        ID that has to match the rule to be found.

    .PARAMETER DisplayName
        DisplayName that has to match the rule to be found.

    .PARAMETER Description
        Description that has to match the rule to be found.

    .PARAMETER Enabled
        Enabledthat has to match the rule to be found.

    .PARAMETER RProfile
        Profile that has to match the rule to be found.

    .PARAMETER Direction
        Direction that has to match the rule to be found.

    .PARAMETER Action
        Action that has to match the rule to be found.

    .OUTPUTS
        A rule corresponding to search parameters, if found, or $null if not found.
        The type of this rule matches the array passed with Rules parameter.

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

    if (-not (Test-Path $PathCSV))
    {
        throw [System.IO.FileNotFoundException]::new("Cannot find Rules CSV file!")
    }

    if (-not $Silent) { Write-Host "Reading $PathCSV..." }
    $CSVRules = Import-Csv $PathCSV

    # Use default rule written in csv to know which filters were used during export, then update rules with the same filters
    $DefaultRule = $CSVRules[0]
    if ($DefaultRule.ID -eq "DefaultRule")
    {
        $Action = $DefaultRule.Action
        $Enabled = $DefaultRule.Enabled
        $Direction = $DefaultRule.Direction
    }
    else { throw "Cannot read default rule in csv, please run Export-FWRules.ps1" }

    $ForwardingParams = @{}
    if ($WhatIf) { $ForwardingParams.Add("WhatIf", $WhatIf) }
    if ($Silent) { $ForwardingParams.Add("Silent", $Silent) }

    $GNFR = @{}
    if ($Action) { $GNFR.Add("Action", $Action) }
    if ($Enabled) { $GNFR.Add("Enabled", $Enabled) }
    if ($Direction) { $GNFR.Add("Direction", $Direction) }


    if (-not $Silent)
    {
        Write-Host "Reading current firewall rules" -NoNewline
        if ($Action -or $Enabled -or $Direction)
        {
            Write-Host " with filters: "  -NoNewline
            if ($Action) { Write-Host "Action" $Action -NoNewline }
            if ($Action -and ($Enabled -or $Direction)) { Write-Host ", " -NoNewline }
            if ($Enabled) { Write-Host "Enabled" $Enabled -NoNewline }
            if (($Action -or $Enabled) -and $Direction) { Write-Host ", " -NoNewline }
            if ($Direction) { Write-Host "Direction" $Direction -NoNewline }
        }
        Write-Host "..."
    }

    # Get all current firewall rules.
    $CurrentRules = Get-NetFirewallRule @GNFR

    # Disable all firewall rules that are not present in CSV.
    for ($i = 0; $i -lt $CurrentRules.Count; $i++)
    {
        $CurrentRule = $CurrentRules[$i]

        $CSVRule = Find-Rule -Rules $CSVRules -ID $CurrentRule.InstanceID
        if (-not $CSVRule)
        {
            # if $CSVRule was not found, check if $CurrentRule has a corresponding CSVRule with ignored ID
            $CSVRule = Find-Rule -Rules $CSVRules -ID ([FWRule]::IgnoreTag) `
                        -DisplayName $CurrentRule.DisplayName `
                        -Description $CurrentRule.Description `
                        -Enabled $CurrentRule.Enabled `
                        -RProfile $CurrentRule.Profile `
                        -Direction $CurrentRule.Direction `
                        -Action $CurrentRule.Action
            if (-not $CSVRule) { Update-EnabledValue -Enabled $false -ComparingRule $CurrentRule @ForwardingParams }
            else { Write-Host "Ignoring" $CurrentRule.DisplayName }
        }
    }

    # Update all rules that match by ID, or create new ones
    for ($i = 1; $i -lt $CSVRules.Count; $i++)
    {
        # $i = 0 is DefaultRule
        $CSVRule = $CSVRules[$i]

        if (-not $Silent) {
            $Activity = "Parsing rule " + $CSVRule.DisplayName
            $PercentComplete = ($i / $CSVRules.Count * 100)
        }
        if ($FastMode)
        {
            # FastMode compares $CSVRules with $CurrentRules, which is an array that comes directly from firewall using Get-NetFirewallRule.
            # It is faster than using Get-FWRule(s) but several properties are missing, so it is ok to enable or disable rules.

            if (-not $Silent) { Write-Progress -CurrentOperation "Checking only Enabled due to FastMode" -Activity $Activity -PercentComplete $PercentComplete }

            $CurrentRule = Find-Rule -Rules $CurrentRules -ID $CSVRule.ID

            # $CurrentRule is a CimInstance.
            if ($CurrentRule) { Update-EnabledValue -Enabled $CSVRule.Enabled -ComparingRule $CurrentRule @ForwardingParams }
            else
            {
                # In CSV file, this rule could have IgnoreTag in ID field.
                if ($CSVRule.ID -ne [FWRule]::IgnoreTag) { Add-FWRule -NewRule $CSVRule @ForwardingParams }
                else { Write-Host "Ignoring" $CSVRule.DisplayName }
            }
        }
        else
        {
            # Regular mode calls Get-FWRule for each rule of CSV, it's slower than Get-NetFirewallRule but all properties are filled in and can be compared.
            $CurrentRule = Get-FWRule -ID $CSVRule.ID -Activity $Activity -PercentComplete $PercentComplete

            # $CurrentRule is a FWRule object.
            if ($CurrentRule) { Update-FWRule -SourceRule $CSVRule -ComparingRule $CurrentRule @ForwardingParams }
            else
            {
                # In CSV file, this rule could have IgnoreTag in ID field.
                if ($CSVRule.ID -ne [FWRule]::IgnoreTag) { Add-FWRule -NewRule $CSVRule @ForwardingParams  }
                else { Write-Host "Ignoring" $CSVRule.DisplayName }
            }
        }
    }


    <#
    .SYNOPSIS
        Updates firewall rules with matching values in CSV file.

    .DESCRIPTION
        Rules present only in CSV files will be added (and enabled).
        Rules present only in Firewall will be disabled (never deleted).
        Rules present in both CSV and Firewall will be updated as per CSV file.
        Please use Export-FWRules, first, to export the CSV files with rules of your firewall

    .PARAMETER PathCSV
        Complete path of CSV file containing rules to check.

    .PARAMETER WhatIf
        Do not actually modify firewall, only show what would happen.

    .PARAMETER Silent
        Do not write anything but errors.

    .PARAMETER FastMode
        Only enable or disable rules.

    .EXAMPLE
        Update-FWRules -PathCSV "$env:USERPROFILE\Desktop\Rules.csv"
        Imports rules from Rules.csv in user's desktop and updates firewall consequently.

    .EXAMPLE
        Update-FWRules -PathCSV "$env:USERPROFILE\Desktop\Rules.csv" -WhatIf
        Only simulate changes in Firewall, but do not actually modify it.

    .EXAMPLE
        Update-FWRules -PathCSV "$env:USERPROFILE\Desktop\Rules.csv" -FastMode
        Fast check and update only Enabled value
    #>
}


Export-ModuleMember -Function Export-FWRules, Update-FWRules
