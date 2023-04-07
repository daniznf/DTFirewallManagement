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
    static [string] $Separator = ", "
}

function Get-FWRule
{
    param (
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
        $LocalAddress = Join-String -Array $Address.LocalAddress -Separator ([FWRule]::Separator)
    }
    else { $LocalAddress = $Address.LocalAddress }

    if ($Address.RemoteAddress -is [System.Array])
    {
        $RemoteAddress = Join-String -Array $Address.RemoteAddress -Separator ([FWRule]::Separator)
    }
    else { $RemoteAddress = $Address.RemoteAddress }

    $Application = $NFRule | Get-NetFirewallApplicationFilter
    $Program = $Application.Program

    $Port = $NFRule | Get-NetFirewallPortFilter
    $Protocol = $Port.Protocol
    if ($Port.LocalPort -is [System.Array])
    {
        $LocalPort = Join-String -Array $Port.LocalPort -Separator ([FWRule]::Separator)
    }
    else { $LocalPort = $Port.LocalPort }

    if ($Port.RemotePort -is [System.Array])
    {
        $RemotePort = Join-String -Array $Port.RemotePort -Separator ([FWRule]::Separator)
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

function Get-FilteredNetFirewallRules {
    param (
        [string]
        $ID,

        [string]
        $DisplayName,

        [string]
        $Group,

        [string]
        $DisplayGroup,

        [ValidateSet("True", "False")]
        [string]
        $Enabled,

        [ValidateSet("Any", "Domain", "Private", "Public")]
        [string]
        $RuleProfile,

        [ValidateSet("Inbound", "Outbound")]
        [string]
        $Direction,

        [ValidateSet("Allow", "Block")]
        [string]
        $Action
    )

    $NFRules = Get-NetFirewallRule

    # Where-Object is more flexible than Get-NetFirewallRule's built-in filters.
    if ($ID) { $NFRules = $NFRules | Where-Object { $_.ID -eq $ID } }
    if ($DisplayName) { $NFRules = $NFRules | Where-Object { $_.DisplayName -like "*$DisplayName*" } }
    if ($Group) { $NFRules = $NFRules | Where-Object { $_.Group -like "*$Group*" } }
    if ($DisplayGroup) { $NFRules = $NFRules | Where-Object { $_.DisplayGroup -like "*$DisplayGroup*" } }
    if ($Enabled) { $NFRules = $NFRules | Where-Object { $_.Enabled -eq $Enabled } }
    if ($RuleProfile) { $NFRules = $NFRules | Where-Object { $_.Profile -eq $RuleProfile } }
    if ($Direction) { $NFRules = $NFRules | Where-Object { $_.Direction -eq $Direction } }
    if ($Action) { $NFRules = $NFRules | Where-Object { $_.Action -eq $Action } }

    return $NFRules

    <#
    .SYNOPSIS
        Gets all NetFirewallRules that correspond to filters, directly from firewall.

    .DESCRIPTION
        Filters firewall rules with passed filters.

    .PARAMETER ID
        Gets only the rule with this ID.

    .PARAMETER DisplayName
        Gets only rules with a DisplayName that contains this value.

    .PARAMETER Group
        Exports only rules with a Group that contains this value.

    .PARAMETER DisplayGroup
        Exports only rules with a DisplayGroup that contains this value.
        This parameter is only used to filter exported rules, and actually depends on $Group parameter of each rule.

    .PARAMETER Enabled
        Exports only rules with this Enabled value.

    .PARAMETER RuleProfile
        Exports only rules with this RuleProfile value.

    .PARAMETER Direction
        Exports only rules with this Direction value.

    .PARAMETER Action
        Exports only rules with this Action value.

    .OUTPUTS
        An array of CimInstance objects.
    #>
}

function Find-Rule {
    param (
        [Parameter(Mandatory, ParameterSetName="CimRules")]
        [Ciminstance[]]
        $CimRules,

        [Parameter(Mandatory, ParameterSetName="FWRules")]
        [FWRule[]]
        $FWRules,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $ID,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $DisplayName,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $Group,

        [Parameter(ParameterSetName="FWRules")]
        [string]
        $Program,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $Enabled,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $RProfile,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $Direction,

        [Parameter(ParameterSetName="CimRules")]
        [Parameter(ParameterSetName="FWRules")]
        [string]
        $Action,

        [Parameter(ParameterSetName="FWRules")]
        [string]
        $Protocol,

        [Parameter(ParameterSetName="FWRules")]
        [string]
        $LocalAddress,

        [Parameter(ParameterSetName="FWRules")]
        [string]
        $LocalPort,

        [Parameter(ParameterSetName="FWRules")]
        [string]
        $RemoteAddress,

        [Parameter(ParameterSetName="FWRules")]
        [string]
        $RemotePort
    )

    $Rules = ""
    if ($PSCmdlet.ParameterSetName -eq "CimRules") { $Rules = $CimRules}
    else { $Rules = $FWRules }

    for ($i = 0; $i -lt $Rules.Length; $i++)
    {
        $Rule = $Rules[$i]

        if ((($ID -eq "") -or ($ID -eq $Rule.ID) -or ($ID -eq $Rule.InstanceID)) -and
            (($DisplayName -eq "") -or ($DisplayName -eq $Rule.DisplayName)) -and
            (($Group -eq "") -or ($Group -eq $Rule.Group)) -and
            (($Enabled -eq "") -or ($Enabled -eq $Rule.Enabled)) -and
            (($RProfile -eq "") -or ($RProfile -eq $Rule.Profile)) -and
            (($Direction -eq "") -or ($Direction -eq $Rule.Direction)) -and
            (($Action -eq "") -or ($Action -eq $Rule.Action)))
        {
            if ($Rule -is [FWRule])
            {
                if ((($Program -eq "") -or ($Program -eq $Rule.Program)) -and
                (($Protocol -eq "") -or ($Protocol -eq $Rule.Protocol)) -and
                (($LocalAddress -eq "") -or ($LocalAddress -eq $Rule.LocalAddress)) -and
                (($LocalPort -eq "") -or ($LocalPort -eq $Rule.LocalPort)) -and
                (($RemoteAddress -eq "") -or ($RemoteAddress -eq $Rule.RemoteAddress)) -and
                (($RemotePort -eq "") -or ($RemotePort -eq $Rule.RemotePort)))
                {
                    return $Rule
                }
            }
            else
            {
                return $Rule
            }
        }
    }

    <#
    .SYNOPSIS
        Finds a rule with parameters equal to given ones, in an array of rules.

    .DESCRIPTION
        Rule can be searched passing any combination of parameters.

    .PARAMETER CimRules
        An array of rules of type CimInstance.

    .PARAMETER FWRules
        An array of rules of type FWRule.

    .PARAMETER ID
        ID that has to be equal to the ID of the rule to be found.

    .PARAMETER DisplayName
        DisplayName that has to be equal to the DisplayName of the rule to be found.

    .PARAMETER Group
        Group that has to be equal to the Group of the rule to be found.

    .PARAMETER Program
        Program that has to be equal to the Program of the rule to be found.

    .PARAMETER Enabled
        Enabled value that has to be equal to the Enabled value of the rule to be found.

    .PARAMETER RProfile
        Profile value that has to be equal to the Profile value of the rule to be found.

    .PARAMETER Direction
        Direction value that has to be equal to the Direction value of the rule to be found.

    .PARAMETER Action
        Action value that has to be equal to the Action value of the rule to be found.

    .PARAMETER Protocol
        Protocol value that has to be equal to the Protocol value of the rule to be found.

    .PARAMETER LocalAddress
        LocalAddress value that has to be equal to the LocalAddress value of the rule to be found.

    .PARAMETER LocalPort
        LocalPort value that has to be equal to the LocalPort value of the rule to be found.

    .PARAMETER RemoteAddress
        RemoteAddress value that has to be equal to the RemoteAddress value of the rule to be found.

    .PARAMETER RemotePort
        RemotePort value that has to be equal to the RemotePort value of the rule to be found.

    .OUTPUTS
        The first rule corresponding to search parameters, if found, or $null if not found.
        The type of this rule depends on the array passed as CimRules or FWRules.

    .EXAMPLE
        Find-Rule -CimRules (Get-NetFirewallRule) -ID "MyRuleID"

    .EXAMPLE
        Find-Rule -FWRules (Get-FWRules) -ID "MyRuleID"
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
    if ($NewRule.LocalAddress -ne [FWRule]::IgnoreTag)
    {
        $LocalAddress = $NewRule.LocalAddress
        $LclAddr = Split-String -String $LocalAddress -Separator ","
        $RuleParams.Add("LocalAddress", $LclAddr)
    }
    if ($NewRule.LocalPort -ne [FWRule]::IgnoreTag)
    {
        $LocalPort = $NewRule.LocalPort
        $LclPrt = Split-String -String $LocalPort -Separator ","
        $RuleParams.Add("LocalPort", $LclPrt)
    }
    if ($NewRule.RemoteAddress -ne [FWRule]::IgnoreTag)
    {
        $RemoteAddress = $NewRule.RemoteAddress
        $RmtAddr = Split-String -String $RemoteAddress -Separator ","
        $RuleParams.Add("RemoteAddress", $RmtAddr)
    }
    if ($NewRule.RemotePort -ne [FWRule]::IgnoreTag)
    {
        $RemotePort = $NewRule.RemotePort
        $RmtPrt = Split-String -String $RemotePort -Separator ","
        $RuleParams.Add("RemotePort", $RmtPrt)
    }
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
        if ($Silent) { $NNFRParams.add("Silent", $Silent) }
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

    if ($SourceRule.ID -ne $ComparingRule.ID) { throw "SourceRule's ID and ComparingRule's ID must be equal."}

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

                # Set-NetFirewallRule will not accept an FWRule
                if ($ComparingRule -is [FWRule])
                {
                    $ComparingRule = Get-NetFirewallRule -ID $ComparingRule.ID
                }

                # Addresses and ports might need an array instead of string.
                if (($AttributeName -eq "LocalAddress") -or ($AttributeName -eq "RemoteAddress") -or
                    ($AttributeName -eq "LocalPort") -or ($AttributeName -eq "RemotePort"))
                {
                    if ($SourceAttribute.Contains(","))
                    {
                        $SrcAttr = Split-String -String $SourceAttribute -Separator ","
                        $SNFRParams.Add($AttributeName, $SrcAttr)
                    }
                    else
                    {
                        $SNFRParams.Add($AttributeName, $SourceAttribute)
                    }
                }
                elseif ($AttributeName -eq "Group")
                {
                    # Group parameter is the source string for the DisplayGroup parameter.
                    # Dot notation and Set-NetFirewallRule is required for Group.
                    $ComparingRule.Group = $SourceAttribute
                }
                elseif ($AttributeName -eq "DisplayName")
                {
                    $ComparingRule.DisplayName = $SourceAttribute
                }
                else
                {
                    $SNFRParams.Add($AttributeName, $SourceAttribute)
                }

                $ComparingRule | Set-NetFirewallRule @SNFRParams
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

    $Members = Get-Member -InputObject $Rule -MemberType Properties
    for ($i = 0; $i -lt $Members.Length; $i++)
    {
        $Member = $Members[$i]
        $Value = Select-Object -InputObject $Rule -ExpandProperty $Member.Name

        if ($Value.Contains("*"))
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

function Test-RuleEqual {
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

    if ((("" -eq $Program) -or ($FWRule.Program -eq $Program)) -and
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
        Tests if this FWRule's attributes are equal to passed attributes.

    .PARAMETER FWRule
        Object of type FWRule to be tested.

    .PARAMETER Program
        Program value that must be equal to rule's Program.

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
                    Approve-NewRule, Test-RuleEqual, Get-FilteredNetFirewallRules, Find-Rule
