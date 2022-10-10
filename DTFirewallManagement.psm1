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
# using Module ".\Modules\FWRule.psm1"

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

    # Create a special rule to be consumed only by Update-Rules, to avoid updating rules that were not exported
    $DefaultRule = [FWRule]::new()
    $DefaultRule.ID = "DefaultRule"
    $DefaultRule.DisplayName = "Default Rule"
    $DefaultRule.Description = "Parameters used when calling exporting rules, do not edit this line!!"
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
                Write-Host "Rules have not been written to File!"
                Exit 1
            }
        }
    }

    $Rules = Get-FirewallRules @GFR
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
        a CSV file that can be used to update Firewall using the command Update-Rules, or just prints them here.

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

function Update-FWRules
{
    param (
        [Parameter(Mandatory)]
        [string]
        $PathCSV,

        [switch]
        $DryRun,

        [switch]
        $Silent,

        [switch]
        $FastMode
    )

    if (-not (Test-Path $PathCSV))
    {
        Write-Output "Cannot find Rules CSV file!"
        exit 1
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
    else
    {
        Write-Host "Cannot read default rule in csv, please run Export-Rules.ps1"
        Remove-Modules
        exit 1
    }

    $ForwardingParams = @{}
    if ($DryRun) { $ForwardingParams.Add("DryRun", $DryRun) }
    if ($Silent) { $ForwardingParams.Add("Silent", $Silent) }

    $GNFR = @{}
    if ($Action) { $GNFR.Add("Action", $Action) }
    if ($Enabled) { $GNFR.Add("Enabled", $Enabled) }
    if ($Direction) { $GNFR.Add("Direction", $Direction) }

    $CSVRuleIDs = [string[]] ( $CSVRules | ForEach-Object ID )

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

    # Much Faster than Get-FirewallRules
    $CurrentRules = Get-NetFirewallRule @GNFR

    # Disable all rules that are not present in CSV
    for ($i = 0; $i -lt $CurrentRules.Count; $i++)
    {
        $CurrentRule = $CurrentRules[$i]
        if (-not ($CSVRuleIDs.Contains($CurrentRule.InstanceID)))
        {
            if ($CurrentRule.Enabled.ToString() -eq "True")
            {
                Update-EnabledValue -Enabled $false -ComparingRule $CurrentRule @ForwardingParams
            }
        }
    }

    # Update all rules that match by ID, or create new ones
    for ($i = 1; $i -lt $CSVRuleIDs.Count; $i++)
    {
        # $i = 0 is DefaultRule
        $CSVRule = $CSVRules[$i]

        if (-not $Silent) {
            $Activity = "Parsing rule " + $CSVRule.DisplayName
            $PercentComplete = ($i / $CSVRuleIDs.Count * 100)
        }
        if ($FastMode)
        {
            if (-not $Silent) { Write-Progress -CurrentOperation "Checking only Enabled due to FastMode" -Activity $Activity -PercentComplete $PercentComplete }

            $RuleFound = $false
            # Search for corresponding rule in CurrentRules (I would not trust $i)
            for ($j = 0; $j -lt $CurrentRules.Count; $j++)
            {
                $CurrentRule = $CurrentRules[$j]
                if ($CurrentRule.InstanceID -eq $CSVRule.ID)
                {
                    Update-EnabledValue -Enabled $CSVRule.Enabled -ComparingRule $CurrentRule @ForwardingParams
                    $RuleFound = $true
                    break
                }
            }

            if ($RuleFound -eq $false)
            {
                # Bug: They should match...
                if (("Enabled" -in $GNFR.Keys -and $GNFR.Keys["Enabled"] -eq "True") -and
                ("Action" -in $GNFR.Keys -and $GNFR.Keys["Action"] -eq "True") -and
                ("Direction" -in $GNFR.Keys -and $GNFR.Keys["Direction"] -eq "True"))
                {
                    Add-Rule -NewRule $CSVRule @ForwardingParams
                }
            }
        }
        else
        {
            $CurrentRule = Get-Rule -ID $CSVRule.ID -Activity $Activity -PercentComplete $PercentComplete

            if ($CurrentRule)
            {
                Update-Rule -SourceRule $CSVRule -ComparingRule $CurrentRule @ForwardingParams
            }
            else
            {
                Add-Rule -NewRule $CSVRule @ForwardingParams
            }
        }
    }


    <#
    .SYNOPSIS
        Updates firewall rules with ones in CSV file.

    .DESCRIPTION
        Rules present only in CSV files will be added (and enabled).
        Rules present only in Firewall will be disabled (never deleted).
        Rules present in both CSV and Firewall will be updated as per CSV file.
        Please use Export-Rules, first, to export the CSV files with rules of your firewall

    .PARAMETER PathCSV
        Complete path of CSV file containing rules to check.

    .PARAMETER DryRun
        Do not actually modify firewall, only show what would happen.

    .PARAMETER Silent
        Do not write anything but errors.

    .PARAMETER FastMode
        Only enable or disable rules.

    .EXAMPLE
        Update-FWRules -PathCSV "$env:USERPROFILE\Desktop\Rules.csv"
        Imports rules from Rules.csv in user's desktop and updates firewall consequently.

    .EXAMPLE
        Update-FWRules -PathCSV "$env:USERPROFILE\Desktop\Rules.csv" -DryRun
        Only simulate changes in Firewall, but do not actually modify it.

    .EXAMPLE
        Update-FWRules -PathCSV "$env:USERPROFILE\Desktop\Rules.csv" -FastMode
        Fast check and update only Enabled value
    #>
}


Export-ModuleMember -Function Export-FWRules, Update-FWRules


