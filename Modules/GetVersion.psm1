function Get-Version {
    $Ver = [Version]::new(0,6,0,0)
    return $Ver
}
function Get-VersionString {
    $Ver = Get-Version
    return  ("DTFirewallManagement v{0}.{1}.{2}" -f $Ver.Major, $Ver.Minor, $Ver.Build)
}

Export-ModuleMember -Function Get-Version, Get-VersionString
