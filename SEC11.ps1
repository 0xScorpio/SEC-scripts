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

    try {
        $smb1Enabled = (Get-ItemProperty -Path $smbRegistryPath -ErrorAction Stop).SMB1
        $smb2Enabled = (Get-ItemProperty -Path $smbRegistryPath -ErrorAction Stop).SMB2

        Write-Host "================================"
        Write-Host "          SMB Versions          "
        Write-Host "================================"
        Write-Host "  SMB1: $(If ($smb1Enabled -eq 1) {'Enabled'})"
        Write-Host "  SMB2: $(If ($smb2Enabled -eq 1) {'Enabled'})"
        Write-Host "________________________________"
        Write-Host ""
        Write-Host ""
    } catch {
        Write-Host "Error accessing registry path: $smbRegistryPath"
    }
}

# Function to check TLS values
function Get-TLSValues {
    $tlsRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

    try {
        $ssl20EnabledClient = (Get-ItemProperty -Path "$tlsRegistryPath\SSL 2.0\Client" -ErrorAction Stop).Enabled
        $ssl20EnabledServer = (Get-ItemProperty -Path "$tlsRegistryPath\SSL 2.0\Server" -ErrorAction Stop).Enabled
        $ssl30EnabledClient = (Get-ItemProperty -Path "$tlsRegistryPath\SSL 3.0\Client" -ErrorAction Stop).Enabled
        $ssl30EnabledServer = (Get-ItemProperty -Path "$tlsRegistryPath\SSL 3.0\Server" -ErrorAction Stop).Enabled
        $tls10EnabledClient = (Get-ItemProperty -Path "$tlsRegistryPath\TLS 1.0\Client" -ErrorAction Stop).Enabled
        $tls10EnabledServer = (Get-ItemProperty -Path "$tlsRegistryPath\TLS 1.0\Server" -ErrorAction Stop).Enabled
        $tls11EnabledClient = (Get-ItemProperty -Path "$tlsRegistryPath\TLS 1.1\Client" -ErrorAction Stop).Enabled
        $tls11EnabledServer = (Get-ItemProperty -Path "$tlsRegistryPath\TLS 1.1\Server" -ErrorAction Stop).Enabled
        $tls12EnabledClient = (Get-ItemProperty -Path "$tlsRegistryPath\TLS 1.2\Client" -ErrorAction Stop).Enabled
        $tls12EnabledServer = (Get-ItemProperty -Path "$tlsRegistryPath\TLS 1.2\Server" -ErrorAction Stop).Enabled

        Write-Host "================================"
        Write-Host "          TLS Versions          "
        Write-Host "================================"
        Write-Host "  Client SSL 2.0: $(If ($ssl20EnabledClient -eq 4294967295 -or $ssl20EnabledClient -eq 1) {'Enabled'})"
        Write-Host "  Server SSL 2.0: $(If ($ssl20EnabledServer -eq 4294967295 -or $ssl20EnabledServer -eq 1) {'Enabled'})"
        Write-Host "  Client SSL 3.0: $(If ($ssl30EnabledClient -eq 4294967295 -or $ssl30EnabledClient -eq 1) {'Enabled'})"
        Write-Host "  Server SSL 3.0: $(If ($ssl30EnabledServer -eq 4294967295 -or $ssl30EnabledServer -eq 1) {'Enabled'})"
        Write-Host "  Client TLS 1.0: $(If ($tls10EnabledClient -eq 4294967295 -or $tls10EnabledClient -eq 1) {'Enabled'})"
        Write-Host "  Server TLS 1.0: $(If ($tls10EnabledServer -eq 4294967295 -or $tls10EnabledServer -eq 1) {'Enabled'})"
        Write-Host "  Client TLS 1.1: $(If ($tls11EnabledClient -eq 4294967295 -or $tls11EnabledClient -eq 1) {'Enabled'})"
        Write-Host "  Server TLS 1.1: $(If ($tls11EnabledServer -eq 4294967295 -or $tls11EnabledServer -eq 1) {'Enabled'})"
        Write-Host "  Client TLS 1.2: $(If ($tls12EnabledClient -eq 4294967295 -or $tls12EnabledClient -eq 1) {'Enabled'})"
        Write-Host "  Server TLS 1.2: $(If ($tls12EnabledServer -eq 4294967295 -or $tls12EnabledServer -eq 1) {'Enabled'})"
        Write-Host "________________________________"
    } catch {
        Write-Host "Error accessing registry path: $tlsRegistryPath"
    }
}

function Get-Hashes {
    $hashesPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"

    try {
        $md5Check = (Get-ItemProperty -Path "$hashesPath\MD5" -ErrorAction Stop).Enabled
        $shaCheck = (Get-ItemProperty -Path "$hashesPath\SHA" -ErrorAction Stop).Enabled
        $sha256Check = (Get-ItemProperty -Path "$hashesPath\SHA256" -ErrorAction Stop).Enabled
        $sha384Check = (Get-ItemProperty -Path "$hashesPath\SHA384" -ErrorAction Stop).Enabled
        $sha512Check = (Get-ItemProperty -Path "$hashesPath\SHA512" -ErrorAction Stop).Enabled

        Write-Host "================================"
        Write-Host "             Hashes             "
        Write-Host "================================"
        Write-Host "   MD5: $(If ($md5Check -eq 4294967295 -or $md5Check -eq 1) {'Enabled'})"
        Write-Host "   SHA: $(If ($shaCheck -eq 4294967295 -or $shaCheck -eq 1) {'Enabled'})"
        Write-Host "   SHA256: $(If ($sha256Check -eq 4294967295 -or $sha256Check -eq 1) {'Enabled'})"
        Write-Host "   SHA384: $(If ($sha384Check -eq 4294967295 -or $sha384Check -eq 1) {'Enabled'})"
        Write-Host "   SHA512: $(If ($sha512Check -eq 4294967295 -or $sha512Check -eq 1) {'Enabled'})"
        Write-Host "________________________________"
    } catch {
        Write-Host "Error accessing registry path: $hashesPath"
    }
}

# Check SMB versions
Get-SMBVersions

# Check TLS values
Get-TLSValues

# Check hashes
Get-Hashes 
