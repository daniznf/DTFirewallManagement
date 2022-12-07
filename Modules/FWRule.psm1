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


class FWRule
{
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
    $FWRuleObj.LocalAddress = $LocalAddress
    $FWRuleObj.RemoteAddress = $RemoteAddress
    $FWRuleObj.Protocol = $Protocol
    $FWRuleObj.LocalPort = $LocalPort
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

function Join-String
{
    param
    (
        [System.Array]
        $Arr,
        [string]
        $Separator
    )

    $toReturn = ""

    if ($Arr)
    {
        for ($i = 0; $i -lt $Arr.Length; $i++) { $toReturn += $Arr[$i] + $Separator }

        if ($toReturn.Contains($Separator)) { $toReturn = $toReturn.Remove($toReturn.LastIndexOf($Separator)) }
    }
    return $toReturn

    <#
    .SYNOPSIS
        Joins input array of string Arr using Separator.

    .PARAMETER Arr
        Array of string to Join-String.

    .PARAMETER Separator
        Separator to use between each string in the array.

    .OUTPUTS
        A string with all the items in Arr separated by Separator.

    .EXAMPLE
        Join-String -Arr ("a", "b", "c") -Separator "; "
        a; b; c
    #>
}

function Split-String
{
    param
    (
        [string]
        $Str,
        [string]
        $Separator
    )

    $splitted = $Str.Split($Separator)
    if ($splitted -is [System.Array])
    {
        $toReturn = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt $splitted.Length; $i++)
        {
            $trimmed = $splitted[$i].Trim()
            if ($trimmed) { $null = $toReturn.Add($trimmed) }
        }
        return $toReturn
    }
    return $splitted

    <#
    .SYNOPSIS
        Splits input string into an array of trimmed strings.
        Only non-empty strings will be returned.

    .PARAMETER Str
        A string to split.

    .PARAMETER Separator
        Separator to use to split the string.

    .OUTPUTS
        An array of strings.

    .EXAMPLE
        Split-String -Str "a;   b; c   ;d" -Separator "; "
        a
        b
        c
        d
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
    if ($NewRule.LocalAddress -ne [FWRule]::IgnoreTag) { $RuleParams.Add("LocalAddress", $NewRule.LocalAddress) }
    if ($NewRule.RemoteAddress -ne [FWRule]::IgnoreTag) { $RuleParams.Add("RemoteAddress", $NewRule.RemoteAddress) }
    if ($NewRule.Protocol -ne [FWRule]::IgnoreTag) { $RuleParams.Add("Protocol", $NewRule.Protocol) }
    if ($NewRule.LocalPort -ne [FWRule]::IgnoreTag) { $RuleParams.Add("LocalPort", $NewRule.LocalPort) }
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

    $WhatIfParam = @{}
    if ($WhatIf) { $WhatIfParam.Add("WhatIf", $WhatIf) }

    if ($SourceRule.DisplayName -ne $ComparingRule.DisplayName)
    {
        if ($SourceRule.DisplayName -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent) { Write-Host "Ignoring DisplayName of" $ComparingRule.DisplayName }
        }
        else
        {
            if (-not $Silent) { Write-Host "Updating DisplayName of" $ComparingRule.DisplayName "to" $SourceRule.DisplayName }
            Set-NetFirewallRule @WhatIfParam -ID $ComparingRule.ID -NewDisplayName $SourceRule.DisplayName
        }
    }
    if ($SourceRule.Program -ne $ComparingRule.Program)
    {
        if ($SourceRule.Program -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent) { Write-Host "Ignoring Program of" $ComparingRule.DisplayName }
        }
        else
        {
            if (-not $Silent) { Write-Host "Updating Program of" $ComparingRule.DisplayName "from" $ComparingRule.Program "to" $SourceRule.Program }
            Set-NetFirewallRule @WhatIfParam -ID $ComparingRule.ID -Program $SourceRule.Program
        }
    }
    if ($SourceRule.Enabled -ne $ComparingRule.Enabled)
    {
        if ($SourceRule.Enabled -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent) { Write-Host "Ignoring Enabled of" $ComparingRule.DisplayName }
        }
        else
        {
            if (-not $Silent) { Write-Host "Updating Enabled of" $ComparingRule.DisplayName "from" $ComparingRule.Enabled "to" $SourceRule.Enabled }
            Set-NetFirewallRule @WhatIfParam -ID $ComparingRule.ID -Enabled $SourceRule.Enabled
        }
    }
    if ($SourceRule.Profile -ne $ComparingRule.Profile)
    {
        if ($SourceRule.Profile -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent) { Write-Host "Ignoring Profile of" $ComparingRule.DisplayName }
        }
        else
        {
            if (-not $Silent) { Write-Host "Updating Profile of" $ComparingRule.DisplayName "from" $ComparingRule.Profile "to"  $SourceRule.Profile }
            Set-NetFirewallRule @WhatIfParam -ID $ComparingRule.ID -Profile $SourceRule.Profile
        }
    }
    if ($SourceRule.Direction -ne $ComparingRule.Direction)
    {
        if ($SourceRule.Direction -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent) { Write-Host "Ignoring Direction of" $ComparingRule.DisplayName }
        }
        else
        {
            if (-not $Silent) { Write-Host "Updating Direction of" $ComparingRule.DisplayName "from" $ComparingRule.Direction "to"  $SourceRule.Direction }
            Set-NetFirewallRule @WhatIfParam -ID $ComparingRule.ID -Direction $SourceRule.Direction
        }
    }
    if ($SourceRule.Action -ne $ComparingRule.Action)
    {
        if ($SourceRule.Action -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent) { Write-Host "Ignoring Action of" $ComparingRule.DisplayName }
        }
        else
        {
            if (-not $Silent) { Write-Host "Updating Action of" $ComparingRule.DisplayName "from" $ComparingRule.Action "to"  $SourceRule.Action }
            Set-NetFirewallRule @WhatIfParam -ID $ComparingRule.ID -Action $SourceRule.Action
        }
    }
    if ($SourceRule.LocalAddress -ne $ComparingRule.LocalAddress)
    {
        if ($SourceRule.LocalAddress -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent) { Write-Host "Ignoring LocalAddress of" $ComparingRule.DisplayName }
        }
        else
        {
            if (-not $Silent) { Write-Host "Updating LocalAddress of" $ComparingRule.DisplayName "from" $ComparingRule.LocalAddress "to"  $SourceRule.LocalAddress }

            $localAddress = ""
            if ($SourceRule.LocalAddress.Contains(",")) { $localAddress = Split-String -Str $SourceRule.LocalAddress -Separator "," }
            else { $localAddress = $SourceRule.LocalAddress }

            Set-NetFirewallRule @WhatIfParam -ID $ComparingRule.ID -LocalAddress $localAddress
        }
    }
    if ($SourceRule.RemoteAddress -ne $ComparingRule.RemoteAddress)
    {
        if ($SourceRule.RemoteAddress -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent) { Write-Host "Ignoring RemoteAddress of" $ComparingRule.DisplayName }
        }
        else
        {
            if (-not $Silent) { Write-Host "Updating RemoteAddress of" $ComparingRule.DisplayName "from" $ComparingRule.RemoteAddress "to"  $SourceRule.RemoteAddress }

            $remoteAddress = ""
            if ($SourceRule.RemoteAddress.Contains(",")) { $remoteAddress = Split-String -Str $SourceRule.RemoteAddress -Separator "," }
            else { $remoteAddress = $SourceRule.RemoteAddress }

            Set-NetFirewallRule @WhatIfParam -ID $ComparingRule.ID -RemoteAddress $remoteAddress
        }
    }
    if ($SourceRule.Protocol -ne $ComparingRule.Protocol)
    {
        if ($SourceRule.Protocol -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent) { Write-Host "Ignoring Protocol of" $ComparingRule.DisplayName }
        }
        else
        {
            if (-not $Silent) { Write-Host "Updating Protocol of" $ComparingRule.DisplayName "from" $ComparingRule.Protocol "to"  $SourceRule.Protocol }
            Set-NetFirewallRule @WhatIfParam -ID $ComparingRule.ID -Protocol $SourceRule.Protocol
        }
    }
    if ($SourceRule.LocalPort -ne $ComparingRule.LocalPort)
    {
        if ($SourceRule.LocalPort -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent) { Write-Host "Ignoring LocalPort of" $ComparingRule.DisplayName }
        }
        else
        {
            if (-not $Silent) { Write-Host "Updating LocalPort of" $ComparingRule.DisplayName "from" $ComparingRule.LocalPort "to"  $SourceRule.LocalPort }

            $localPort = ""
            if ($SourceRule.LocalPort.Contains(",")) { $localPort = Split-String -Str $SourceRule.LocalPort -Separator "," }
            else { $localPort = $SourceRule.LocalPort }

            Set-NetFirewallRule @WhatIfParam -ID $ComparingRule.ID -LocalPort $localPort
        }
    }
    if ($SourceRule.RemotePort -ne $ComparingRule.RemotePort)
    {
        if ($SourceRule.RemotePort -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent)  { Write-Host "Ignoring RemotePort of" $ComparingRule.DisplayName }
        }
        else
        {
            if (-not $Silent) { Write-Host "Updating RemotePort of" $ComparingRule.DisplayName "from" $ComparingRule.RemotePort "to"  $SourceRule.RemotePort }

            $remotePort = ""
            if ($SourceRule.RemotePort.Contains(",")) { $remotePort = Split-String -Str $SourceRule.RemotePort -Separator "," }
            else { $remotePort = $SourceRule.RemotePort }

            Set-NetFirewallRule @WhatIfParam -ID $ComparingRule.ID -RemotePort $remotePort
        }
    }
    if ($SourceRule.Description -ne $ComparingRule.Description)
    {
        if ($SourceRule.Description -eq [FWRule]::IgnoreTag)
        {
            if (-not $Silent) { Write-Host "Ignoring Description of" $ComparingRule.DisplayName }
        }
        else
        {
            if (-not $Silent) { Write-Host "Updating Description of" $ComparingRule.DisplayName "to" $SourceRule.Description }
            Set-NetFirewallRule @WhatIfParam -ID $ComparingRule.ID -Description $SourceRule.Description
        }
    }

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
