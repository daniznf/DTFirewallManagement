function Get-Version {
    $Ver = [version]::new(0,4,1,0)
    return $Ver
}

Export-ModuleMember -Function Get-Version
