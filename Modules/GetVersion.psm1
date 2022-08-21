function Get-Version {
    $Ver = [version]::new(0,3,0,0)    
    return $Ver
}

Export-ModuleMember -Function Get-Version
