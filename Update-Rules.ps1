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

using Module ".\Modules\GetVersion.psm1"
using Module ".\Modules\TestAdministrator\TestAdministrator.psm1"
using Module ".\Modules\Rules.psm1"

param(
    [Parameter(Mandatory)]
    [string]
    $PathCSV,
    
    [switch]
    $DryRun,

    [switch]
    $Silent,

    [switch]
    $FastMode,

    [switch]
    $Version
)

# $StartTime = Get-Date

function  Remove-Modules {
    Remove-Module GetVersion
    Remove-Module TestAdministrator
    Remove-Module Rules
}

if ($Version)
{
    Get-VersionString | Write-Host
    Remove-Modules
    exit
}

if (-not $(Test-Administrator))
{
    Write-Output "Restarting as administrator..."
    Restart-AsAdministrator -BypassExecutionPolicy -CommandPath $MyInvocation.MyCommand.Path -BoundParameters $PSBoundParameters
    
    Remove-Modules
    exit
}

if (-not (Test-Path $PathCSV))
{
    Write-Output "Cannot find Rules CSV file!"
    Remove-Modules
    exit 1
}

if (-not $Silent) { Write-Host "Reading $PathCSV..." }
$CSVRules = Import-Csv $PathCSV


# Use default rule written in csv to know filters used during export, then update rules with same filters
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
        
        # Search for corresponding rule in CurrentRules (I would not trust $i)
        for ($j = 0; $j -lt $CurrentRules.Count; $j++)
        {
            $CurrentRule = $CurrentRules[$j]
            if ($CurrentRule.InstanceID -eq $CSVRule.ID)
            {
                Update-EnabledValue -Enabled $CSVRule.Enabled -ComparingRule $CurrentRule @ForwardingParams
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
        else { Add-Rule -NewRule $CSVRule @ForwardingParams }
    }
}

# $EndTime = Get-Date
# Write-Host ($EndTime - $StartTime)

Remove-Modules

<#
.SYNOPSIS
Updates Firewall rules by following CSV file passed in arguments.

.DESCRIPTION
Rules present only in CSV files will be added (and enabled).
Rules present only in Firewall will be disabled (never deleted).
Rules present in both CSV and Firewall will be updated as per CSV file.
Please use Export-Rules, first, to export the CSV files with rules of your firewall

Update-Rules is part of Daniele's Tools Firewall Management scripts

.PARAMETER PathCSV
Complete path of CSV file containing rules to check

.PARAMETER DryRun
Do not actually modify firewall

.PARAMETER Silent
Do not write anything but errors

.PARAMETER FastMode
Only enable or disable rules

.PARAMETER Version
Show script version

.EXAMPLE
.\Update-Rules.ps1 -PathCSV "$env:USERPROFILE\Desktop\Rules.csv"
Imports rules from Rules.csv in user's desktop and updates firewall consequently

.EXAMPLE
.\Update-Rules.ps1 -PathCSV "$env:USERPROFILE\Desktop\Rules.csv" -DryRun
Only simulate changes in Firewall, but do not actually modify it

.EXAMPLE
.\Update-Rules.ps1 -PathCSV "$env:USERPROFILE\Desktop\Rules.csv" -FastMode
Fast check and update only Enabled value

.LINK
https://github.com/daniznf/DTFirewallManagement
#>
