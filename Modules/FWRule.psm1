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

using module ".\StringHelper.psm1"

class FWRule
{
    [string]$ID
    [string]$DisplayName
    [string]$Program
    [string]$Enabled
    [string]$Profile
    [string]$Direction
    [string]$Action
    [string]$Protocol
    [string]$LocalAddress
    [string]$LocalPort
    [string]$RemoteAddress
    [string]$RemotePort
    [string]$Description

    static [string] $IgnoreTag = "_ignore"
}

function Get-FWRules
{
    param
    (
        [string]
        [ValidateSet("Allow", "Block")]
        $Action,

        [string]
        [ValidateSet("True", "False")]
        $Enabled,

        [string]
        [ValidateSet("Inbound", "Outbound")]
        $Direction,

        [string]
        $DisplayName
    )

    $GNFR = @{}

    if ($Action) { $GNFR.Add("Action", $Action) }
    if ($Enabled) { $GNFR.Add("Enabled", $Enabled) }
    if ($Direction) { $GNFR.Add("Direction", $Direction) }

    $NFRules = Get-NetFirewallRule @GNFR

    if ($DisplayName) { $NFRules = $NFRules | Where-Object { $_.DisplayName -match $DisplayName } }

    # If only one rule is found, $NFRules is not an array.
    if ($NFRules -isnot [System.Array]) { $NFRules = @($NFRules) }

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

    <#
    .SYNOPSIS
        Returns all firewall rules that match given arguments.

    .PARAMETER Action
        Return all rules with equal Action value.

    .PARAMETER Enabled
        Return all rules with equal Enabled value.

    .PARAMETER Direction
        Return all rules with equal Direction value.

    .PARAMETER DisplayName
        Return all rules with matching DisplayName value.

    .OUTPUTS
        A list of objects of type FWRule.
    #>
}

function Get-FWRule
{
    param(
        [Parameter(Mandatory)]
        [string]
        $ID,

        [string]
        $Activity,

        [int]
        $PercentComplete
    )

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

    <#
    .SYNOPSIS
        Returns a single firewall rule that matches ID.

    .PARAMETER ID
        The ID of the rule of whom to fetch infos.

    .PARAMETER Activity
        The name of the Activity to display in progress bar.

    .PARAMETER PercentComplete
        The level of PercentComplete for the progress bar.

    .OUTPUTS
        An object of type FWRule.
    #>
}

function Parse-FWRule
{
    param(
        [Parameter(Mandatory)]
        [CimInstance]
        $NFRule,

        [string]
        $Activity,

        [int]
        $PercentComplete
    )

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

    if ($Address.LocalAddress -is [System.Array])
    {
        $LocalAddress = Join-String -Arr $Address.LocalAddress -Separator ", "
    }
    else { $LocalAddress = $Address.LocalAddress }

    if ($Address.RemoteAddress -is [System.Array])
    {
        $RemoteAddress = Join-String -Arr $Address.RemoteAddress -Separator ", "
    }
    else { $RemoteAddress = $Address.RemoteAddress }

    if ($Activity) { Write-Progress -CurrentOperation "Application" @ProgressParams }
    $Application = $NFRule | Get-NetFirewallApplicationFilter
    $Program = $Application.Program

    if ($Activity) { Write-Progress -CurrentOperation "Port" @ProgressParams }
    $Port = $NFRule | Get-NetFirewallPortFilter
    $Protocol = $Port.Protocol
    if ($Port.LocalPort -is [System.Array])
    {
        $LocalPort = Join-String -Arr $Port.LocalPort -Separator ", "
    }
    else { $LocalPort = $Port.LocalPort }

    if ($Port.RemotePort -is [System.Array])
    {
        $RemotePort = Join-String -Arr $Port.RemotePort -Separator ", "
    }
    else { $RemotePort = $Port.RemotePort }

    if ($Activity) { Write-Progress -CurrentOperation "Sum up" @ProgressParams }
    $FWRuleObj = [FWRule]::new()
    $FWRuleObj.ID = $ID
    $FWRuleObj.DisplayName = $DisplayName
    $FWRuleObj.Program = $Program
    $FWRuleObj.Enabled = $Enabled
    $FWRuleObj.Profile = $RProfile
    $FWRuleObj.Direction = $Direction
    $FWRuleObj.Action = $Action
    $FWRuleObj.Protocol = $Protocol
    $FWRuleObj.LocalAddress = $LocalAddress
    $FWRuleObj.LocalPort = $LocalPort
    $FWRuleObj.RemoteAddress = $RemoteAddress
    $FWRuleObj.RemotePort = $RemotePort
    $FWRuleObj.Description = $Description

    return $FWRuleObj

    <#
    .SYNOPSIS
        Fills all properties of a new FWRule object by querying Firewall services.

    .PARAMETER NFRule
        The NetFirewallRule object to scan.

    .PARAMETER Activity
        The name of the Activity to display in progress bar.

    .PARAMETER PercentComplete
        The level of PercentComplete for the progress bar.

    .OUTPUTS
        An object of type FWRule.
    #>
}

function  Add-FWRule
{
    param
    (
        [Parameter(Mandatory)]
        [FWRule]
        $NewRule,

        [switch]
        $Silent,

        [switch]
        $WhatIf
    )

    $WhatIfParam = @{}
    if ($WhatIf) { $WhatIfParam.Add("WhatIf", $WhatIf) }

    if (-not $Silent) { Write-Host "Adding rule" $NewRule.DisplayName }

    $RuleParams = @{}
    # If ID is missing, it will be automatically generated.
    if ($NewRule.ID -ne [FWRule]::IgnoreTag) { $RuleParams.Add("ID", $NewRule.ID) }
    if ($NewRule.DisplayName -ne [FWRule]::IgnoreTag) { $RuleParams.Add("DisplayName", $NewRule.DisplayName) }
    if ($NewRule.Program -ne [FWRule]::IgnoreTag) { $RuleParams.Add("Program", $NewRule.Program) }
    if ($NewRule.Enabled -ne [FWRule]::IgnoreTag) { $RuleParams.Add("Enabled", $NewRule.Enabled) }
    if ($NewRule.Profile -ne [FWRule]::IgnoreTag) { $RuleParams.Add("Profile", $NewRule.Profile) }
    if ($NewRule.Direction -ne [FWRule]::IgnoreTag) { $RuleParams.Add("Direction", $NewRule.Direction) }
    if ($NewRule.Action -ne [FWRule]::IgnoreTag) { $RuleParams.Add("Action", $NewRule.Action) }
    if ($NewRule.Protocol -ne [FWRule]::IgnoreTag) { $RuleParams.Add("Protocol", $NewRule.Protocol) }
    if ($NewRule.LocalAddress -ne [FWRule]::IgnoreTag) { $RuleParams.Add("LocalAddress", $NewRule.LocalAddress) }
    if ($NewRule.LocalPort -ne [FWRule]::IgnoreTag) { $RuleParams.Add("LocalPort", $NewRule.LocalPort) }
    if ($NewRule.RemoteAddress -ne [FWRule]::IgnoreTag) { $RuleParams.Add("RemoteAddress", $NewRule.RemoteAddress) }
    if ($NewRule.RemotePort -ne [FWRule]::IgnoreTag) { $RuleParams.Add("RemotePort", $NewRule.RemotePort) }
    if ($NewRule.Description -ne [FWRule]::IgnoreTag) { $RuleParams.Add("Description", $NewRule.Description) }

    # New-NetFirewallRule will write results to host
    New-NetFirewallRule @WhatIfParam @RuleParams


    <#
    .SYNOPSIS
        Adds a new NetFirewallRule to firewall with values copied from NewRule.

    .PARAMETER NewRule
        An object of type FWRule with all informations necessary to add a new rule to firewall.

    .PARAMETER Silent
        Do not write anything but errors and new added rules.

    .PARAMETER WhatIf
        Do not actually modify Firewall.
    #>
}

function Update-FWRule
{
    param
    (
        [Parameter(Mandatory)]
        [FWRule]
        $SourceRule,

        [Parameter(Mandatory)]
        [FWRule]
        $ComparingRule,

        [switch]
        $Silent,

        [switch]
        $WhatIf
    )

    if ($SourceRule.ID -ne $ComparingRule.ID) { throw "SourceRule's ID and ComparingRule's ID must match."}

    $UAParams = @{}
    if ($Silent) { $UAParams.Add("Silent", $true) }
    if ($WhatIf) { $UAParams.Add("WhatIf", $true) }
    $UAParams.Add("SourceRule", $SourceRule)
    $UAParams.Add("ComparingRule", $ComparingRule)

    Update-Attribute @UAParams -AttributeName "DisplayName"
    Update-Attribute @UAParams -AttributeName "Program"
    Update-Attribute @UAParams -AttributeName "Enabled"
    Update-Attribute @UAParams -AttributeName "Profile"
    Update-Attribute @UAParams -AttributeName "Direction"
    Update-Attribute @UAParams -AttributeName "Action"
    Update-Attribute @UAParams -AttributeName "Protocol"
    Update-Attribute @UAParams -AttributeName "LocalAddress"
    Update-Attribute @UAParams -AttributeName "LocalPort"
    Update-Attribute @UAParams -AttributeName "RemoteAddress"
    Update-Attribute @UAParams -AttributeName "RemotePort"
    Update-Attribute @UAParams -AttributeName "Description"

    <#
    .SYNOPSIS
        Updates the NetFirewallRule (searched by ID) with values from SourceRule, if they are not equal to values in ComparingRule.

    .PARAMETER SourceRule
        FWRule object to compare (and copy) values from.

    .PARAMETER ComparingRule
        FWRule object to compare values against.

    .PARAMETER Silent
        Do not write anything but errors.

    .PARAMETER WhatIf
        Do not actually modify Firewall.
    #>
}

function Update-Attribute
{
    param
    (
        [Parameter(Mandatory)]
        [string]
        $AttributeName,
        [Parameter(Mandatory)]
        [FWRule]
        $SourceRule,
        [Parameter(Mandatory)]
        [FWRule]
        $ComparingRule,
        [switch]
        $Silent,
        [switch]
        $WhatIf
    )

    $SourceAttribute = $SourceRule | Select-Object -ExpandProperty $AttributeName
    $ComparingAttribute = $ComparingRule | Select-Object -ExpandProperty $AttributeName

    if ($SourceAttribute -ne $ComparingAttribute)
    {
        if ($SourceAttribute -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent)
            {
                Write-Host "Ignoring $AttributeName of" $ComparingRule.DisplayName
            }
        }
        else
        {
            if (-not $Silent)
            {
                if (($AttributeName -eq "DisplayName") -or ($AttributeName -eq "Description"))
                {
                    Write-Host "Updating $AttributeName of" $ComparingRule.DisplayName `
                               "to '$SourceAttribute'"
                }
                else
                {
                    Write-Host "Updating $AttributeName of" $ComparingRule.DisplayName `
                               "from '$ComparingAttribute' to '$SourceAttribute'"
                }
            }

            # Addresses and ports might need an array instead of string.
            if (($AttributeName -eq "LocalAddress") -or ($AttributeName -eq "RemoteAddress") -or
                ($AttributeName -eq "LocalPort") -or ($AttributeName -eq "RemotePort"))
            {
                if ($SourceAttribute.Contains(",")) { $SourceAttribute = Split-String -Str $SourceAttribute -Separator "," }
            }

            $SNFRParams = @{}
            $SNFRParams.Add("ID", $ComparingRule.ID)

            # Updating DisplayName is done with -NewDisplayName instead of -DisplayName.
            if ($AttributeName -eq "DisplayName") { $SNFRParams.Add("NewDisplayName", $SourceAttribute) }
            else { $SNFRParams.Add($AttributeName, $SourceAttribute) }

            if ($WhatIf) { $SNFRParams.Add("WhatIf", $true) }

            Set-NetFirewallRule @SNFRParams
        }
    }


    <#
    .SYNOPSIS
        Updates the value of an attribute of the NetFirewallRule (searched by ID) with the value of the attribute of SourceRule,
        if it is not equal to attribute in ComparingRule.

    .PARAMETER AttributeName
        Name of attribute to compare and update.

    .PARAMETER SourceRule
        FWRule object to compare (and copy) attribute's value from.

    .PARAMETER ComparingRule
        FWRule object to compare attribute's value against.

    .PARAMETER Silent
        Do not write anything but errors.

    .PARAMETER WhatIf
        Do not actually modify Firewall.
    #>
}

function Update-EnabledValue
{
    param
    (
        [Parameter(Mandatory)]
        [string]
        $Enabled,

        [Parameter(Mandatory)]
        [CimInstance]
        $ComparingRule,

        [switch]
        $Silent,

        [switch]
        $WhatIf
    )

    $WhatIfParam = @{}
    if ($WhatIf) { $WhatIfParam.Add("WhatIf", $WhatIf) }

    if ($Enabled -ne $ComparingRule.Enabled)
    {
        if ($Enabled -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent) { Write-Host "Ignoring Enabled of" $ComparingRule.DisplayName }
        }
        else
        {
            if (-not $Silent) { Write-Host "Updating Enabled of" $ComparingRule.DisplayName "from" $ComparingRule.Enabled "to" $Enabled }
            Set-NetFirewallRule @WhatIfParam -ID $ComparingRule.ID -Enabled $Enabled
        }
    }

    <#
    .SYNOPSIS
        Updates only the Enabled parameter of NetFirewallRule with same ID as ComparingRule
        if passed Enabled argument does not match ComparingRule.Enabled.

    .PARAMETER ComparingRule
        CimInstance object to check values against.

    .PARAMETER Silent
        Do not write anything but errors.

    .PARAMETER WhatIf
        Do not actually modify firewall.
    #>
}

# `

Export-ModuleMember -Function Get-FWRules, Get-FWRule, Update-FWRule, Update-EnabledValue, Add-FWRule
