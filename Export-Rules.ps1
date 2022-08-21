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
    [string]
    # Complete path of CSV file where to write rules of firewall.
    # If null, rules will just be printed out in stdout
    $PathCSV,

    [string]
    # Read only rules with this Action value
    [ValidateSet("Allow", "Block")]
    $Action,

    [string]
    # Read only rules with this Enabled value
    [ValidateSet("True", "False")]
    $Enabled,

    [string]
    # Read only rules with this Direction value
    [ValidateSet("Inbound", "Outbound")]
    $Direction,

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

$GR = @{}
    if ($Action) { $GR.Add("Action", $Action) }
    if ($Enabled) { $GR.Add("Enabled", $Enabled) }
    if ($Direction) { $GR.Add("Direction", $Direction) }

if (-not $(Test-Administrator))
{
    Write-Output "Restarting as administrator..."
    Restart-AsAdministrator -BypassExecutionPolicy -CommandPath $MyInvocation.MyCommand.Path -BoundParameters $PSBoundParameters
    
    Remove-Modules
    exit
}

# Create a special rule to be consumed only by Update-Rules, to avoid updating rules that were not exported
$DefaultRule = [Rule]::new()
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

if ($PathCSV -ne "")
{
    if (Test-Path $PathCSV)
    {
        $overwrite = Read-Host -Prompt "File exists. Overwrite it? [y/n]"
        
        if ($overwrite -eq "y") 
        { 
            Remove-Item $PathCSV 
        }
        else
        {
            Write-Output "Rules have not been written to File!"
            Remove-Modules
            Exit 1
        }
    }    
}

$Rules = Get-Rules @GR
$RuleList.AddRange($Rules)

if ($PathCSV -ne "")
{
    $RuleList | Export-Csv $PathCSV -NoTypeInformation
}
else
{
    $RuleList
}

Remove-Modules

# `

<#
.SYNOPSIS
Exports in CSV firewall rules as per input parameters

.DESCRIPTION
Export-Rules is part of Daniele's Tools Firewall Management scripts

.EXAMPLE
.\Export-Rules.ps1
Displays matching rules in this shell

.EXAMPLE
.\Export-Rules.ps1 -PathCSV "$env:USERPROFILE\Desktop\Rules.csv"
Exports to user's desktop all firewall rules in Rules.csv

.EXAMPLE
.\Export-Rules.ps1 -PathCSV .\test.csv -Action Allow -Enabled True -Profile Private -Direction Inbound
Exports matching rules in test.csv


#>
