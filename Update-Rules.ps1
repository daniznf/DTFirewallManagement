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
using Module ".\Modules\Rule.psm1"
using Module ".\Modules\GetRules.psm1"

param(
    [Parameter(Mandatory)]
    [string]
    # Complete path of CSV file containing rules to check
    $PathCSV,
    
    [switch]
    # Do not actually modify firewall
    $DryRun,

    [switch]
    # Don't write anything but errors
    $Silent,

    [switch]
    # Show script version
    $Version
)

function  Remove-Modules {
    Remove-Module GetVersion
    Remove-Module TestAdministrator
    Remove-Module Rule
    Remove-Module GetRules
}

if ($Version)
{
    $Ver = Get-Version
    Write-Host "Version" $Ver.ToString()
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

$GNFR = @{}
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

# Much Faster than Get-Rules @GNFR
$CurrentRules = Get-NetFirewallRule @GNFR

# Disable all rules that are not present in CSV
for ($i = 0; $i -lt $CurrentRules.Count; $i++)
{
    $CurrentRule = $CurrentRules[$i]
    if (-not ($CSVRuleIDs.Contains($CurrentRule.InstanceID)))
    {
        if ($CurrentRule.Enabled.ToString() -eq "True")
        {
            if (-not $Silent) { Write-Host "Disabling: " $CurrentRule.DisplayName }
            if (-not $DryRun) { Set-NetFirewallRule -ID $CurrentRule.InstanceID -Enabled "False" }
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
    
    $CurrentRule = Get-Rule -ID $CSVRule.ID -Activity $Activity -PercentComplete $PercentComplete
    
    if ($CurrentRule)
    {
        # Check that CurrentRule equals CSVRule, or update it
        if ($CSVRule.DisplayName -ne $CurrentRule.DisplayName)
        {
            if (-not $Silent) { Write-Host "Updating: " $CurrentRule.DisplayName " -> " $CSVRule.DisplayName }
            if (-not $DryRun) { Set-NetFirewallRule -ID $CSVRule.ID -NewDisplayName $CSVRule.DisplayName }
        }
        if ($CSVRule.Program -ne $CurrentRule.Program)
        {
            if (-not $Silent) { Write-Host "Updating: " $CurrentRule.DisplayName " -> " $CSVRule.Program }
            if (-not $DryRun) { Set-NetFirewallRule -ID $CSVRule.ID -Program $CSVRule.Program }
        }
        if ($CSVRule.Enabled -ne $CurrentRule.Enabled)
        {
            if (-not $Silent) { Write-Host "Updating: " $CurrentRule.DisplayName " -> " $CSVRule.Enabled }
            if (-not $DryRun) { Set-NetFirewallRule -ID $CSVRule.ID -Enabled $CSVRule.Enabled }
        }
        if ($CSVRule.Profile -ne $CurrentRule.Profile)
        {
            if (-not $Silent) { Write-Host "Updating: " $CurrentRule.DisplayName " -> " $CSVRule.Profile }
            if (-not $DryRun) { Set-NetFirewallRule -ID $CSVRule.ID -Profile $CSVRule.Profile }
        }
        if ($CSVRule.Direction -ne $CurrentRule.Direction)
        {
            if (-not $Silent) { Write-Host "Updating: " $CurrentRule.DisplayName " -> " $CSVRule.Direction }
            if (-not $DryRun) { Set-NetFirewallRule -ID $CSVRule.ID -Direction $CSVRule.Direction }
        }
        if ($CSVRule.Action -ne $CurrentRule.Action)
        {
            if (-not $Silent) { Write-Host "Updating: " $CurrentRule.DisplayName " -> " $CSVRule.Action }
            if (-not $DryRun) { Set-NetFirewallRule -ID $CSVRule.ID -Action $CSVRule.Action }
        }
        if ($CSVRule.LocalAddress -ne $CurrentRule.LocalAddress)
        {
            if (-not $Silent) { Write-Host "Updating: " $CurrentRule.DisplayName " -> " $CSVRule.LocalAddress }
            if (-not $DryRun) { Set-NetFirewallRule -ID $CSVRule.ID -LocalAddress $CSVRule.LocalAddress }
        }
        if ($CSVRule.RemoteAddress -ne $CurrentRule.RemoteAddress)
        {
            if (-not $Silent) { Write-Host "Updating: " $CurrentRule.DisplayName " -> " $CSVRule.RemoteAddress }
            if (-not $DryRun) { Set-NetFirewallRule -ID $CSVRule.ID -RemoteAddress $CSVRule.RemoteAddress }
        }
        if ($CSVRule.Protocol -ne $CurrentRule.Protocol)
        {
            if (-not $Silent) { Write-Host "Updating: " $CurrentRule.DisplayName " -> " $CSVRule.Protocol }
            if (-not $DryRun) { Set-NetFirewallRule -ID $CSVRule.ID -Protocol $CSVRule.Protocol }
        }
        if ($CSVRule.LocalPort -ne $CurrentRule.LocalPort)
        {
            if (-not $Silent) { Write-Host "Updating: " $CurrentRule.DisplayName " -> " $CSVRule.LocalPort }
            if (-not $DryRun) { Set-NetFirewallRule -ID $CSVRule.ID -LocalPort $CSVRule.LocalPort }
        }
        if ($CSVRule.RemotePort -ne $CurrentRule.RemotePort)
        {
            if (-not $Silent) { Write-Host "Updating: " $CurrentRule.DisplayName " -> " $CSVRule.RemotePort }
            if (-not $DryRun) { Set-NetFirewallRule -ID $CSVRule.ID -RemotePort $CSVRule.RemotePort }
        }
        if ($CSVRule.Description -ne $CurrentRule.Description)
        {
            if (-not $Silent) { Write-Host "Updating: " $CurrentRule.DisplayName " -> " $CSVRule.Description }
            if (-not $DryRun) { Set-NetFirewallRule -ID $CSVRule.ID -Description $CSVRule.Description }
        }
    }
    else
    {
        # Add CSVRule
        if (-not $Silent) { Write-Host "Adding rule: " $CSVRule.DisplayName }
        if (-not $DryRun)
        {
            New-NetFirewallRule `
                -ID $CSVRule.ID `
                -DisplayName $CSVRule.DisplayName `
                -Program $CSVRule.Program `
                -Enabled $CSVRule.Enabled `
                -Profile $CSVRule.Profile `
                -Direction $CSVRule.Direction `
                -Action $CSVRule.Action `
                -LocalAddress $CSVRule.LocalAddress `
                -RemoteAddress $CSVRule.RemoteAddress `
                -Protocol $CSVRule.Protocol `
                -LocalPort $CSVRule.LocalPort `
                -RemotePort $CSVRule.RemotePort `
                -Description $CSVRule.Description
        }
    }
}

Remove-Module GetRules
Remove-Module TestAdministrator

<#
.SYNOPSIS
Updates Firewall rules by following CSV file passed in arguments.

.DESCRIPTION
Rules present only in CSV files will be added (and enabled).
Rules present only in Firewall will be disabled (never deleted).
Rules present in both CSV and Firewall will be updated as per CSV file.
Please use Export-Rules, first, to export the CSV files with rules of your firewall

Update-Rules is part of Daniele's Tools Firewall Management scripts

.EXAMPLE
.\Update-Rules.ps1 -PathCSV "$env:USERPROFILE\Desktop\Rules.csv"
Imports rules from Rules.csv in user's desktop and updates firewall consequently

.EXAMPLE
.\Update-Rules.ps1 -PathCSV Rules.csv -Direction Inbound
#>
