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
    # DisplayGroup is not editable, but is reported in system's graphical instrumentation.
    [string]$Group
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
        $DisplayName,

        [string]
        $Group,

        [string]
        $DisplayGroup
    )

    $GNFRParams = @{}

    if ($Action) { $GNFRParams.Add("Action", $Action) }
    if ($Enabled) { $GNFRParams.Add("Enabled", $Enabled) }
    if ($Direction) { $GNFRParams.Add("Direction", $Direction) }

    $NFRules = Get-NetFirewallRule @GNFRParams

    # Where-Object is more flexible than Get-NetFirewallRule's built-in filters. It permits:
    # - Combining DisplayName with other filters
    # - Filtering using -match
    if ($DisplayName) { $NFRules = $NFRules | Where-Object { $_.DisplayName -match $DisplayName } }
    if ($Group) { $NFRules = $NFRules | Where-Object { $_.Group -match $Group } }
    if ($DisplayGroup) { $NFRules = $NFRules | Where-Object { $_.DisplayGroup -match $DisplayGroup } }

    # If only one rule is found, $NFRules is not an array.
    if ($NFRules -isnot [System.Array]) { $NFRules = @($NFRules) }

    $NFRulesCount = $NFRules.Count

    $OutRules = New-Object System.Collections.ArrayList

    for ($i = 0; $i -lt $NFRulesCount; $i++)
    {
        $NFRule = $NFRules[$i]

        $Activity = "Parsing rule " + $NFRule.DisplayName
        $PercentComplete = ($i / $NFRulesCount * 100)

        $OutRules.Add((Get-FWRule -NFRule $NFRule -Activity $Activity -PercentComplete $PercentComplete)) > $null
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

    .PARAMETER Group
        Return all rules with matching Group value.

    .PARAMETER DisplayGroup
        Return all rules with matching DisplayGroup value.

    .OUTPUTS
        A list of objects of type FWRule.
    #>
}

function Get-FWRule
{
    param(
        [Parameter(Mandatory, ParameterSetName = "ID")]
        [string]
        $ID,

        [Parameter(Mandatory, ParameterSetName = "NF")]
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

    if ($PSCmdlet.ParameterSetName -eq "ID")
    {
        $NFRule = Get-NetFirewallRule -ID $ID -ErrorAction Ignore
        if ($null -eq $NFRule) { return $null }
    }
    else
    {
        $ID = $NFRule.InstanceID
    }

    # $Name = $NFRule.Name
    $DisplayName = $NFRule.DisplayName
    $Group = $NFRule.Group

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
    $FWRuleObj.Group = $Group
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
        Retrieves all properties of a firewall rule ands returns a new FWRule object
        by querying Firewall services.

    .PARAMETER ID
        The ID of the firewall rule to scan.

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

    $NNFRParams = @{}
    if ($WhatIf) { $NNFRParams.Add("WhatIf", $WhatIf) }

    if (-not $Silent) { Write-Host "Adding rule" $NewRule.DisplayName }

    $RuleParams = @{}
    # If ID is missing, it will be automatically generated.
    if ($NewRule.ID -ne [FWRule]::IgnoreTag) { $RuleParams.Add("ID", $NewRule.ID) }
    if ($NewRule.DisplayName -ne [FWRule]::IgnoreTag) { $RuleParams.Add("DisplayName", $NewRule.DisplayName) }
    # Group must be handled by Update-Attribute
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

    $AddedRule = New-NetFirewallRule @NNFRParams @RuleParams

    # Dot notation and Set-NetFirewallRule is required for Group.
    if (($AddedRule) -and ($NewRule.Group -ne ""))
    {
        if ($Silent) { NNFRParams.add("Silent", $Silent) }
        Update-Attribute -AttributeName "Group" -SourceAttribute $NewRule.Group -ComparingCimRule $AddedRule @NNFRParams
    }

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
    $UAParams.Add("ComparingFWRule", $ComparingRule)

    Update-Attribute @UAParams -AttributeName "DisplayName" -SourceAttribute $SourceRule.DisplayName
    Update-Attribute @UAParams -AttributeName "Group" -SourceAttribute $SourceRule.Group
    Update-Attribute @UAParams -AttributeName "Program" -SourceAttribute $SourceRule.Program
    Update-Attribute @UAParams -AttributeName "Enabled" -SourceAttribute $SourceRule.Enabled
    Update-Attribute @UAParams -AttributeName "Profile" -SourceAttribute $SourceRule.Profile
    Update-Attribute @UAParams -AttributeName "Direction" -SourceAttribute $SourceRule.Direction
    Update-Attribute @UAParams -AttributeName "Action" -SourceAttribute $SourceRule.Action
    Update-Attribute @UAParams -AttributeName "Protocol" -SourceAttribute $SourceRule.Protocol
    Update-Attribute @UAParams -AttributeName "LocalAddress" -SourceAttribute $SourceRule.LocalAddress
    Update-Attribute @UAParams -AttributeName "LocalPort" -SourceAttribute $SourceRule.LocalPort
    Update-Attribute @UAParams -AttributeName "RemoteAddress" -SourceAttribute $SourceRule.RemoteAddress
    Update-Attribute @UAParams -AttributeName "RemotePort" -SourceAttribute $SourceRule.RemotePort
    Update-Attribute @UAParams -AttributeName "Description" -SourceAttribute $SourceRule.Description

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
        [Parameter(Mandatory,ParameterSetName="FWRule")]
        [Parameter(Mandatory,ParameterSetName="CimRule")]
        [string]
        $AttributeName,
        [Parameter(ParameterSetName="FWRule")]
        [Parameter(ParameterSetName="CimRule")]
        [string]
        $SourceAttribute,
        [Parameter(Mandatory,ParameterSetName="FWRule")]
        [FWRule]
        $ComparingFWRule,
        [Parameter(Mandatory,ParameterSetName="CimRule")]
        [CimInstance]
        $ComparingCimRule,
        [switch]
        $Silent,
        [switch]
        $WhatIf
    )

    if (($null -eq $SourceAttribute) -or ("" -eq $SourceAttribute)) { return }

    if ($PSCmdlet.ParameterSetName -eq "FWRule")
    {
        $ComparingRule = $ComparingFWRule
    }
    else
    {
        $ComparingRule = $ComparingCimRule
    }

    if ($SourceAttribute -eq [FWRule]::IgnoreTag)
    {
        if (-not $Silent) { Write-Host "Ignoring $AttributeName of" $ComparingRule.DisplayName }
    }
    else
    {
        if (($ComparingRule -is [CimInstance]) -and ($AttributeName -notin "ID", "Name",
        "DisplayName", "Description", "DisplayGroup", "Group", "Enabled",
        "Profile", "Platform", "Direction", "Action", "EdgeTraversalPolicy",
        "LooseSourceMapping", "LocalOnlyMapping", "Owner",
        "PrimaryStatus", "Status", "EnforcementStatus",
        "PolicyStoreSource", "PolicyStoreSourceType", "RemoteDynamicKeywordAddresses"))
        {
            $ComparingRule = Get-FWRule -NFRule $ComparingCimRule
        }

        $ComparingAttribute = $ComparingRule | Select-Object -ExpandProperty $AttributeName

        if ($SourceAttribute -ne $ComparingAttribute)
        {
            $SNFRParams = @{}
            if ($WhatIf) { $SNFRParams.Add("WhatIf", $true) }

            if (-not $Silent)
            {
                Write-Host "Updating $AttributeName of " -NoNewline
                if (($AttributeName -eq "DisplayName"))
                {
                    Write-Host $ComparingRule.ID
                }
                else
                {
                    Write-Host $ComparingRule.DisplayName
                }

                Write-Host "from :" $ComparingAttribute
                Write-Host "to   :" $SourceAttribute
            }

            # Addresses and ports might need an array instead of string.
            if (($AttributeName -eq "LocalAddress") -or ($AttributeName -eq "RemoteAddress") -or
                ($AttributeName -eq "LocalPort") -or ($AttributeName -eq "RemotePort"))
            {
                if ($SourceAttribute.Contains(",")) { $SourceAttribute = Split-String -Str $SourceAttribute -Separator "," }
            }

            # Group parameter is the source string for the DisplayGroup parameter.
            if ($AttributeName -eq "Group")
            {
                # Set-NetFirewallRule will not accept an FWRule
                if ($ComparingRule -is [FWRule])
                {
                    $ComparingRule = Get-NetFirewallRule -ID $ComparingRule.ID
                }
                # Dot notation and Set-NetFirewallRule is required for Group.
                $ComparingRule.Group = $SourceAttribute
                $ComparingRule | Set-NetFirewallRule @SNFRParams
            }
            else
            {
                $SNFRParams.Add("ID", $ComparingRule.ID)

                # Updating DisplayName is done with -NewDisplayName instead of -DisplayName.
                if ($AttributeName -eq "DisplayName") { $SNFRParams.Add("NewDisplayName", $SourceAttribute) }
                else { $SNFRParams.Add($AttributeName, $SourceAttribute) }

                Set-NetFirewallRule @SNFRParams
            }
        }
    }


    <#
    .SYNOPSIS
        Updates the NetFirewallRule (searched by ID) with value of SourceAttribute, if it is not equal to ComparingRule.

    .PARAMETER AttributeName
        Name of attribute to compare and update.

    .PARAMETER SourceAttribute
        Value to compare (and copy) to ComparingRule's attribute.

    .PARAMETER ComparingFWRule
        FWRule object to compare SourceAttribute against.

    .PARAMETER ComparingCimRule
        CimInstance object to compare SourceAttribute against.

    .PARAMETER Silent
        Do not write anything but errors.

    .PARAMETER WhatIf
        Do not actually modify Firewall.
    #>
}


# `

Export-ModuleMember -Function Get-FWRules, Get-FWRule, Update-FWRule, Update-Attribute, Add-FWRule
