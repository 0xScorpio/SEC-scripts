Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [11]
  ____) |
 |_____/ 

_______________________________________________
[SEC11] Reads SMB/TLS/Hashes via Registry Editor
_______________________________________________
"@ -ForegroundColor Cyan


########################### DISPLAY CURRENT SMB/TLS CONFIGURATION ########################### 

# Function to check SMB versions
function Get-SMBVersions {
    $smbRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

    $smb1Enabled = (Get-ItemProperty -Path $smbRegistryPath).SMB1
    $smb2Enabled = (Get-ItemProperty -Path $smbRegistryPath).SMB2

    Write-Host "================================"
    Write-Host "          SMB Versions          "
    Write-Host "================================"
    Write-Host "  SMB1: $(If ($smb1Enabled -eq 1) {'Enabled'})"
    Write-Host "  SMB2: $(If ($smb2Enabled -eq 1) {'Enabled'})"
    Write-Host "________________________________"
    Write-Host ""
    Write-Host ""
}

# Function to check TLS values
function Get-TLSValues {
    $tlsRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

    $ssl20EnabledClient = (Get-ItemProperty -Path "$tlsRegistryPath\SSL 2.0\Client").Enabled
    $ssl20EnabledServer = (Get-ItemProperty -Path "$tlsRegistryPath\SSL 2.0\Server").Enabled
    $ssl30EnabledClient = (Get-ItemProperty -Path "$tlsRegistryPath\SSL 3.0\Client").Enabled
    $ssl30EnabledServer = (Get-ItemProperty -Path "$tlsRegistryPath\SSL 3.0\Server").Enabled
    $tls10EnabledClient = (Get-ItemProperty -Path "$tlsRegistryPath\TLS 1.0\Client").Enabled
    $tls10EnabledServer = (Get-ItemProperty -Path "$tlsRegistryPath\TLS 1.0\Server").Enabled
    $tls11EnabledClient = (Get-ItemProperty -Path "$tlsRegistryPath\TLS 1.1\Client").Enabled
    $tls11EnabledServer = (Get-ItemProperty -Path "$tlsRegistryPath\TLS 1.1\Server").Enabled
    $tls12EnabledClient = (Get-ItemProperty -Path "$tlsRegistryPath\TLS 1.2\Client").Enabled
    $tls12EnabledServer = (Get-ItemProperty -Path "$tlsRegistryPath\TLS 1.2\Server").Enabled

    Write-Host "================================"
    Write-Host "          TLS Versions          "
    Write-Host "================================"
    Write-Host "  Client SSL 2.0: $(If ($ssl20EnabledClient -eq 4294967295) {'Enabled'})"
    Write-Host "  Server SSL 2.0: $(If ($ssl20EnabledServer -eq 4294967295) {'Enabled'})"
    Write-Host "  Client SSL 3.0: $(If ($ssl30EnabledClient -eq 4294967295) {'Enabled'})"
    Write-Host "  Server SSL 3.0: $(If ($ssl30EnabledServer -eq 4294967295) {'Enabled'})"
    Write-Host "  Client TLS 1.0: $(If ($tls10EnabledClient -eq 4294967295) {'Enabled'})"
    Write-Host "  Server TLS 1.0: $(If ($tls10EnabledServer -eq 4294967295) {'Enabled'})"
    Write-Host "  Client TLS 1.1: $(If ($tls11EnabledClient -eq 4294967295) {'Enabled'})"
    Write-Host "  Server TLS 1.1: $(If ($tls11EnabledServer -eq 4294967295) {'Enabled'})"
    Write-Host "  Client TLS 1.2: $(If ($tls12EnabledClient -eq 4294967295) {'Enabled'})"
    Write-Host "  Server TLS 1.2: $(If ($tls12EnabledServer -eq 4294967295) {'Enabled'})"
    Write-Host "________________________________"
}

function Get-Hashes {
    $hashesPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"

    $md5Check = (Get-ItemProperty -Path "$hashesPath\MD5").Enabled
    $shaCheck = (Get-ItemProperty -Path "$hashesPath\SHA").Enabled
    $sha256Check = (Get-ItemProperty -Path "$hashesPath\SHA256").Enabled
    $sha384Check = (Get-ItemProperty -Path "$hashesPath\SHA384").Enabled
    $sha512Check = (Get-ItemProperty -Path "$hashesPath\SHA512").Enabled

    Write-Host "================================"
    Write-Host "             Hashes             "
    Write-Host "================================"
    Write-Host "   MD5: $(If ($md5Check -eq 4294967295) {'Enabled'})"
    Write-Host "   SHA: $(If ($shaCheck -eq 4294967295) {'Enabled'})"
    Write-Host "   SHA256: $(If ($sha256Check -eq 4294967295) {'Enabled'})"
    Write-Host "   SHA384: $(If ($sha384Check -eq 4294967295) {'Enabled'})"
    Write-Host "   SHA512: $(If ($sha512Check -eq 4294967295) {'Enabled'})"
    Write-Host "________________________________"
}

# Check SMB versions
Get-SMBVersions

# Check TLS values
Get-TLSValues

# Check hashes
Get-Hashes 