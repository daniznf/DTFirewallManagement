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

function Get-FWRule
{
    param(
        [Parameter(Mandatory, ParameterSetName = "ID")]
        [string]
        $ID,

        [Parameter(Mandatory, ParameterSetName = "NF")]
        [CimInstance]
        $NFRule
    )

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

    $Description = $NFRule.Description
    $Enabled = $NFRule.Enabled
    $RProfile = $NFRule.Profile
    $Direction = $NFRule.Direction
    $Action = $NFRule.Action

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

    $Application = $NFRule | Get-NetFirewallApplicationFilter
    $Program = $Application.Program

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

    $Approved, $ErrorMessage = Approve-NewRule -Rule $NewRule
    if (-not $Approved )
    {
        if (-not $Silent) { Write-Host -BackgroundColor DarkRed ($ErrorMessage) }
        return
    }

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

        if ($SourceAttribute.Contains("*"))
        {
            if ($ComparingAttribute -notlike $SourceAttribute)
            {
                Write-Host -BackgroundColor DarkRed ("Attribute $AttributeName of rule " +
                     """" + $ComparingRule.DisplayName + """ does not match search pattern ""$SourceAttribute"" " +
                    "but there are not enaugh informations to correct it. Rule will be disabled.")

                $UNFRParams = @{}
                if ($WhatIf) { $UNFRParams.Add("WhatIf", $true) }
                if ($Silent) { $UNFRParams.Add("Silent", $true) }

                if ($ComparingRule -is [CimInstance]) { $UNFRParams.Add("ComparingCimRule", $ComparingRule) }
                else { $UNFRParams.Add("ComparingFWRule", $ComparingRule)}

                Update-Attribute -AttributeName "Enabled" -SourceAttribute "False" @UNFRParams
            }
            # else Nothing to change
        }
        else
        {
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
            # else Nothing to change
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

function Approve-NewRule {
    param (
        [Parameter(Mandatory)]
        [FWRule]
        $Rule
    )

    $members = Get-Member -InputObject $Rule -MemberType Properties
    for ($i = 0; $i -lt $members.Length; $i++)
    {
        $member = $members[$i]
        $value = Select-Object -InputObject $Rule -ExpandProperty $member.Name

        if ($value.Contains("*"))
        {
            return $false, "New rule cannot contain ""*"" in any of its attributes."
        }
    }

    return $true, ""


    <#
    .SYNOPSIS
        Checks if all attributes of this new rule are valid.

    .PARAMETER Rule
        Rule to check.

    .OUTPUTS
        An array of two elements: $true and an empty string if the rule is valid,
        otherwise $false and the error message.
    #>
}

function Test-RuleMatch {
    param (
        [FWRule]
        $FWRule,

        [string]
        $Program,

        [string]
        $Protocol,

        [string]
        $LocalAddress,

        [string]
        $LocalPort,

        [string]
        $RemoteAddress,

        [string]
        $RemotePort
    )

    if ((("" -eq $Program) -or ($FWRule.Program -match $Program)) -and
        (("" -eq $Protocol) -or ($FWRule.Protocol -eq $Protocol)) -and
        (("" -eq $LocalAddress) -or ($FWRule.LocalAddress -eq $LocalAddress)) -and
        (("" -eq $LocalPort) -or ($FWRule.LocalPort -eq $LocalPort)) -and
        (("" -eq $RemoteAddress) -or ($FWRule.RemoteAddress -eq $RemoteAddress)) -and
        (("" -eq $RemotePort) -or ($FWRule.RemotePort -eq $RemotePort)))
      {
        return $true
      }
      else
      {
        return $false
      }

    <#
    .DESCRIPTION
        Tests if this FWRule's attributes satisfy parameters.

    .PARAMETER FWRule
        Object of type FWRule to be tested.

    .PARAMETER Program
        Program value that must match rule's Program.

    .PARAMETER Protocol
        Protocol value that must be equal to rule's Protocol.

    .PARAMETER LocalAddress
        LocalAddress value that must be equal to rule's LocalAddress.

    .PARAMETER LocalPort
        LocalPort value that must be equal to rule's LocalPort.

    .PARAMETER RemoteAddress
        RemoteAddress value that must be equal to rule's RemoteAddress.

    .PARAMETER RemotePort
        RemotePort value that must be equal to rule's RemotePort.

    .OUTPUTS
        $true if all FWRule's attributes either are empty or satisfy passed parameters, otherwise $false.
    #>
}

# `

Export-ModuleMember -Function Get-FWRule, Add-FWRule, Update-FWRule, Update-Attribute, `
                    Approve-NewRule, Test-RuleMatch
