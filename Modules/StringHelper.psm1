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

function Join-String {
    param (
        [Parameter(Mandatory)]
        [System.Array]
        $Array,

        [string]
        $Separator
    )

    $toReturn = ""

    for ($i = 0; $i -lt $Array.Length; $i++)
    {
        $toReturn += $Array[$i].ToString() + $Separator
    }

    if ($toReturn.Contains($Separator)) { $toReturn = $toReturn.Remove($toReturn.LastIndexOf($Separator)) }

    return $toReturn

    <#
    .SYNOPSIS
        Joins input array of string Arr using Separator.

    .PARAMETER Arr
        Array of strings to join.

    .PARAMETER Separator
        Separator to use between each string in the array.

    .OUTPUTS
        A string with all the items in Arr separated by Separator.

    .EXAMPLE
        Join-String -Array ("a", "b", "c") -Separator "; "
        a; b; c
    #>
}

function Split-String {
    param (
        [Parameter(Mandatory)]
        [string]
        $String,

        [string]
        $Separator
    )

    $Splitted = $String.Split($Separator)

    if ($Splitted -is [System.Array])
    {
        for ($i = 0; $i -lt $Splitted.Length; $i++)
        {
            $Splitted[$i] = $Splitted[$i].Trim()
        }
    }

    return $Splitted

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
        Split-String -String "a;   b; c   ;d" -Separator "; "
        a
        b
        c
        d
    #>
}

Export-ModuleMember -Function Join-String, Split-String
