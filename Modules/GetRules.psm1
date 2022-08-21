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

using Module ".\Rule.psm1"

function Get-Rules {
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
        Returns all rules that match given arguments AAAAAAAAA

        .OUTPUTS
        A list of objects of type Rule
    #>

    $GNFR = @{}
    if ($Action) { $GNFR.Add("Action", $Action) }
    if ($Enabled) { $GNFR.Add("Enabled", $Enabled) }
    if ($Direction) { $GNFR.Add("Direction", $Direction) }
    
    $Rules = Get-NetFirewallRule @GNFR
    $TotRules = $Rules.Count

    $OutRules = New-Object System.Collections.ArrayList

    for ($i = 0; $i -lt $Rules.Count; $i++)
    {
        $RuleI = $Rules[$i]
        $DisplayName = $RuleI.DisplayName

        $Activity = "Parsing rule $DisplayName"
        $PercentComplete = ($i / $TotRules * 100)
        
        $OutRules.Add((Parse-Rule -NFRule $RuleI -Activity $Activity -PercentComplete $PercentComplete)) > $null
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
        Returns a single Rule object that matches ID

        .PARAMETER ID
        The ID of the Rule to fetch infos of

        .PARAMETER Activity
        The name of the Activity to display in progress bar

        .PARAMETER PercentComplete
        The level of PercentComplete for the progress bar

        .OUTPUTS
        An object of type Rule
    #>

    $NFRule = Get-NetFirewallRule -ID $ID -ErrorAction Ignore
    
    $Parsed = $null
    if ($NFRule)
    {
        $ProgressParams = @{
                Activity = $Activity
                PercentComplete = $PercentComplete
            }

        $Parsed = Parse-Rule $NFRule @ProgressParams
    }
    
    return $Parsed
}


function Parse-Rule {
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
        Fills all properties of passed rule

        .PARAMETER NFRule
        The NetFirewallRule to scan

        .PARAMETER Activity
        The name of the Activity to display in progress bar

        .PARAMETER PercentComplete
        The level of PercentComplete for the progress bar

        .OUTPUTS
        An object of type Rule
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
    $Profile = $NFRule.Profile
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
    $RuleObj = [Rule]::new()
    $RuleObj.ID = $ID
    $RuleObj.DisplayName = $DisplayName
    $RuleObj.Program = $Program
    $RuleObj.Enabled = $Enabled
    $RuleObj.Profile = $Profile
    $RuleObj.Direction = $Direction
    $RuleObj.Action = $Action
    $RuleObj.LocalAddress = $LocalAddress
    $RuleObj.RemoteAddress = $RemoteAddress
    $RuleObj.Protocol = $Protocol
    $RuleObj.LocalPort = $LocalPort
    $RuleObj.RemotePort = $RemotePort
    $RuleObj.Description = $Description
        
    return $RuleObj
}

Export-ModuleMember -Function Get-Rules,Get-Rule

# Remove-Module Rule

<#
.SYNOPSIS
Retrieves firewall rules in Rule custom objects, containing also Address, Application path, Port 

.DESCRIPTION
Get-Rules is part of Daniele's Tools Firewall Management scripts
#>
