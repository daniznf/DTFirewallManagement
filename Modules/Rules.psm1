﻿<#
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

class FWRule {
    [string]$ID
    [string]$DisplayName
    [string]$Program
    [string]$Enabled
    [string]$Profile
    [string]$Direction
    [string]$Action
    [string]$LocalAddress
    [string]$RemoteAddress
    [string]$Protocol
    [string]$LocalPort
    [string]$RemotePort
    [string]$Description
}

function Get-FirewallRules {
    param(
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
    <#
        .SYNOPSIS
        Returns all firewall rules that match given arguments

        .OUTPUTS
        A list of objects of type FWRule
    #>

    $GNFR = @{}
    if ($Action) { $GNFR.Add("Action", $Action) }
    if ($Enabled) { $GNFR.Add("Enabled", $Enabled) }
    if ($Direction) { $GNFR.Add("Direction", $Direction) }
    
    $NFRules = Get-NetFirewallRule @GNFR
    $NFRulesCount = $NFRules.Count

    $OutRules = New-Object System.Collections.ArrayList

    for ($i = 0; $i -lt $NFRulesCount; $i++)
    {
        $NFRule = $NFRules[$i]

        $Activity = "Parsing rule " + $NFRule.DisplayName
        $PercentComplete = ($i / $NFRulesCount * 100)
        
        $OutRules.Add((Parse-FWRule -NFRule $NFRule -Activity $Activity -PercentComplete $PercentComplete)) > $null
    }
    
    return $OutRules
}

function Get-Rule {
    param(
        [Parameter(Mandatory)]
        [string]
        $ID,
        [string]
        $Activity,
        [int]
        $PercentComplete
    )

    <#
        .SYNOPSIS
        Returns a single FWRule object that matches ID

        .PARAMETER ID
        The ID of the rule of whom to fetch infos

        .PARAMETER Activity
        The name of the Activity to display in progress bar

        .PARAMETER PercentComplete
        The level of PercentComplete for the progress bar

        .OUTPUTS
        An object of type FWRule
    #>
    
    $NFRule = Get-NetFirewallRule -ID $ID -ErrorAction Ignore
    
    $Parsed = $null
    if ($NFRule)
    {
        $ProgressParams = @{
                Activity = $Activity
                PercentComplete = $PercentComplete
            }

        $Parsed = Parse-FWRule $NFRule @ProgressParams
    }
    
    return $Parsed
}

function Parse-FWRule {
    param(
        [Parameter(Mandatory)]
        [CimInstance]
        $NFRule,
        [string]
        $Activity,
        [int]
        $PercentComplete
    )

    <#
        .SYNOPSIS
        Fills all properties of a new FWRule object by querying Firewall services

        .PARAMETER NFRule
        The NetFirewallRule object to scan

        .PARAMETER Activity
        The name of the Activity to display in progress bar

        .PARAMETER PercentComplete
        The level of PercentComplete for the progress bar

        .OUTPUTS
        An object of type FWRule
    #>

    $ProgressParams = @{
        Activity = $Activity
        PercentComplete = $PercentComplete
    }
    
    $ID = $NFRule.InstanceID
    # $Name = $NFRule.Name
    $DisplayName = $NFRule.DisplayName

    if ($Activity) { Write-Progress -CurrentOperation "Basic infos" @ProgressParams }
    $Description = $NFRule.Description
    $Enabled = $NFRule.Enabled
    $RProfile = $NFRule.Profile
    $Direction = $NFRule.Direction
    $Action = $NFRule.Action
        
    if ($Activity) { Write-Progress -CurrentOperation "Address" @ProgressParams }
    $Address = $NFRule | Get-NetFirewallAddressFilter
    $LocalAddress = $Address.LocalAddress
    $RemoteAddress = $Address.RemoteAddress
    
    if ($Activity) { Write-Progress -CurrentOperation "Application" @ProgressParams }
    $Application = $NFRule | Get-NetFirewallApplicationFilter
    $Program = $Application.Program
    
    if ($Activity) { Write-Progress -CurrentOperation "Port" @ProgressParams }
    $Port = $NFRule | Get-NetFirewallPortFilter
    $Protocol = $Port.Protocol
    $RemotePort = $Port.RemotePort
    $LocalPort = $Port.LocalPort
    
    if ($Activity) { Write-Progress -CurrentOperation "Sum up" @ProgressParams }
    $FWRuleObj = [FWRule]::new()
    $FWRuleObj.ID = $ID
    $FWRuleObj.DisplayName = $DisplayName
    $FWRuleObj.Program = $Program
    $FWRuleObj.Enabled = $Enabled
    $FWRuleObj.Profile = $RProfile
    $FWRuleObj.Direction = $Direction
    $FWRuleObj.Action = $Action
    $FWRuleObj.LocalAddress = $LocalAddress
    $FWRuleObj.RemoteAddress = $RemoteAddress
    $FWRuleObj.Protocol = $Protocol
    $FWRuleObj.LocalPort = $LocalPort
    $FWRuleObj.RemotePort = $RemotePort
    $FWRuleObj.Description = $Description
        
    return $FWRuleObj
}

function  Add-Rule {
    param (
        [Parameter(Mandatory)]
        [FWRule]
        $NewRule,
        [switch]
        $Silent,
        [switch]
        $DryRun
    )
    <#
        .SYNOPSIS
        Adds a new NetFirewallRule with values from NewRule 

        .PARAMETER Silent
        Do not write anything but errors

        .PARAMETER DryRun
        Do not actually modify Firewall
    #>
    
    if (-not $Silent) { Write-Host "Adding rule " $NewRule.DisplayName }
    if (-not $DryRun)
    {
        New-NetFirewallRule `
            -ID $NewRule.ID `
            -DisplayName $NewRule.DisplayName `
            -Program $NewRule.Program `
            -Enabled $NewRule.Enabled `
            -Profile $NewRule.Profile `
            -Direction $NewRule.Direction `
            -Action $NewRule.Action `
            -LocalAddress $NewRule.LocalAddress `
            -RemoteAddress $NewRule.RemoteAddress `
            -Protocol $NewRule.Protocol `
            -LocalPort $NewRule.LocalPort `
            -RemotePort $NewRule.RemotePort `
            -Description $NewRule.Description
    }
}

function Update-Rule {
    param (
        [Parameter(Mandatory)]
        [FWRule]
        $SourceRule,
        [Parameter(Mandatory)]
        [FWRule]
        $ComparingRule,
        [switch]
        $Silent,
        [switch]
        $DryRun
    )
    <#
        .SYNOPSIS
        Updates NetFirewallRule (searching by ID of ComparingRule) with values from SourceRule 
        if they do not match values in ComparingRule
        
        .PARAMETER SourceRule
        FWRule object to copy values from

        .PARAMETER ComparingRule
        FWRule object to check values against

        .PARAMETER Silent
        Do not write anything but errors

        .PARAMETER DryRun
        Do not actually modify Firewall
    #>
        
    if ($SourceRule.DisplayName -ne $ComparingRule.DisplayName)
    {
        if (-not $Silent) 
        { 
            Write-Host "Updating" $ComparingRule.DisplayName "DisplayName to" $SourceRule.DisplayName 
        }
        if (-not $DryRun) { Set-NetFirewallRule -ID $ComparingRule.ID -NewDisplayName $SourceRule.DisplayName }
    }
    if ($SourceRule.Program -ne $ComparingRule.Program)
    {
        if (-not $Silent) 
        { 
            Write-Host "Updating" $ComparingRule.DisplayName ": Program from" $ComparingRule.Program "to" $SourceRule.Program 
        }
        if (-not $DryRun) { Set-NetFirewallRule -ID $ComparingRule.ID -Program $SourceRule.Program }
    }
    if ($SourceRule.Enabled -ne $ComparingRule.Enabled)
    {
        if (-not $Silent) 
        { 
            Write-Host "Updating" $ComparingRule.DisplayName ": Enabled from" $ComparingRule.Enabled "to" $SourceRule.Enabled 
        }
        if (-not $DryRun) { Set-NetFirewallRule -ID $ComparingRule.ID -Enabled $SourceRule.Enabled }
    }
    if ($SourceRule.Profile -ne $ComparingRule.Profile)
    {
        if (-not $Silent) 
        { 
            Write-Host "Updating" $ComparingRule.DisplayName ": Profile from" $ComparingRule.Profile "to"  $SourceRule.Profile 
        }
        if (-not $DryRun) { Set-NetFirewallRule -ID $ComparingRule.ID -Profile $SourceRule.Profile }
    }
    if ($SourceRule.Direction -ne $ComparingRule.Direction)
    {
        if (-not $Silent) 
        { 
            Write-Host "Updating" $ComparingRule.DisplayName ": Direction from" $ComparingRule.Direction "to"  $SourceRule.Direction 
        }
        if (-not $DryRun) { Set-NetFirewallRule -ID $ComparingRule.ID -Direction $SourceRule.Direction }
    }
    if ($SourceRule.Action -ne $ComparingRule.Action)
    {
        if (-not $Silent) 
        { 
            Write-Host "Updating" $ComparingRule.DisplayName ": Action from" $ComparingRule.Action "to"  $SourceRule.Action 
        }
        if (-not $DryRun) { Set-NetFirewallRule -ID $ComparingRule.ID -Action $SourceRule.Action }
    }
    if ($SourceRule.LocalAddress -ne $ComparingRule.LocalAddress)
    {
        if (-not $Silent) 
        { 
            Write-Host "Updating" $ComparingRule.DisplayName ": LocalAddress from" $ComparingRule.LocalAddress "to"  $SourceRule.LocalAddress 
        }
        if (-not $DryRun) { Set-NetFirewallRule -ID $ComparingRule.ID -LocalAddress $SourceRule.LocalAddress }
    }
    if ($SourceRule.RemoteAddress -ne $ComparingRule.RemoteAddress)
    {
        if (-not $Silent) 
        { 
            Write-Host "Updating" $ComparingRule.DisplayName ": RemoteAddress from" $ComparingRule.RemoteAddress "to"  $SourceRule.RemoteAddress 
        }
        if (-not $DryRun) { Set-NetFirewallRule -ID $ComparingRule.ID -RemoteAddress $SourceRule.RemoteAddress }
    }
    if ($SourceRule.Protocol -ne $ComparingRule.Protocol)
    {
        if (-not $Silent) 
        { 
            Write-Host "Updating" $ComparingRule.DisplayName ": Protocol from" $ComparingRule.Protocol "to"  $SourceRule.Protocol 
        }
        if (-not $DryRun) { Set-NetFirewallRule -ID $ComparingRule.ID -Protocol $SourceRule.Protocol }
    }
    if ($SourceRule.LocalPort -ne $ComparingRule.LocalPort)
    {
        if (-not $Silent) 
        { 
            Write-Host "Updating" $ComparingRule.DisplayName ": LocalPort from" $ComparingRule.LocalPort "to"  $SourceRule.LocalPort 
        }
        if (-not $DryRun) { Set-NetFirewallRule -ID $ComparingRule.ID -LocalPort $SourceRule.LocalPort }
    }
    if ($SourceRule.RemotePort -ne $ComparingRule.RemotePort)
    {
        if (-not $Silent) 
        { 
            Write-Host "Updating" $ComparingRule.DisplayName ": RemotePort from" $ComparingRule.RemotePort "to"  $SourceRule.RemotePort 
        }
        if (-not $DryRun) { Set-NetFirewallRule -ID $ComparingRule.ID -RemotePort $SourceRule.RemotePort }
    }
    if ($SourceRule.Description -ne $ComparingRule.Description)
    {
        if (-not $Silent) 
        { 
            Write-Host "Updating" $ComparingRule.DisplayName "Description to" $SourceRule.Description 
        }
        if (-not $DryRun) { Set-NetFirewallRule -ID $ComparingRule.ID -Description $SourceRule.Description }
    }   
}

function Update-EnabledValue {
    param (
        [Parameter(Mandatory)]
        [string]
        $Enabled,
        [Parameter(Mandatory)]
        [CimInstance]
        $ComparingRule,
        [switch]
        $Silent,
        [switch]
        $DryRun
    )
    <#
        .SYNOPSIS
        Updates only the Enabled parameter of NetFirewallRule (searching by ID of ComparingRule)
        if it does not match ComparingRule.Enabled

        .PARAMETER ComparingRule
        FWRule object to check values against

        .PARAMETER Silent
        Do not write anything but errors

        .PARAMETER DryRun
        Do not actually modify firewall
    #>
    if ($Enabled -ne $ComparingRule.Enabled)
    {
        if (-not $Silent) 
        { 
            Write-Host "Updating" $ComparingRule.DisplayName " Enabled from" $ComparingRule.Enabled "to" $Enabled 
        }
        if (-not $DryRun) { Set-NetFirewallRule -ID $ComparingRule.ID -Enabled $Enabled }
    }
}

Export-ModuleMember -Function Get-FirewallRules,Get-Rule,Update-Rule,Update-EnabledValue,Add-Rule
Export-ModuleMember -Variable FWRule


