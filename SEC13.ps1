Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [13]
  ____) |
 |_____/ 
"@ -ForegroundColor Cyan

Write-Host ""
Write-Host "__________________________________________________________________________________________________________"
Write-Host "[SEC13] Checks service account credentials, ensuring bad login thresholds (1) and account lockout checking"
Write-Host "__________________________________________________________________________________________________________"
Write-Host @"

"@ -ForegroundColor Cyan


$username = Read-Host 'In order to check credentials, we need to ensure the account is not locked out or
hasnt surpassed any bad password counter limits. Please enter the account for review'

# Define the threshold for bad login attempts
$maxBadLogins = 1

# Get the user object from Active Directory
$user = Get-ADUser -Identity $username -Properties badPwdCount, lockoutTime

# Check if the account is locked out
if ($user.lockoutTime -ne 0) {
    Write-Host "The account $username is currently locked out. Unlock the account first!"
} elseif ($user.badPwdCount -ge $maxBadLogins) {
    Write-Host "The account $username has exceeded the maximum allowed login attempts. Please try again after 60 minutes."
} else {
    # Perform the credential check here
    $credential = Get-Credential -Message 'Enter your credentials for verification:'
    
    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("", $credential.UserName, $credential.GetNetworkCredential().Password)
    
    if ($directoryEntry.psbase.name -ne $null) {
        Write-Host "Authentication successful!"
    } else {
        Write-Host "Authentication failed. Please check your credentials."
    }
    # After credential check, ensure account is not locked:
    $user = Get-ADUser -Identity $username -Properties lockoutTime
    if ($user.lockoutTime -ne 0) {
        Write-Host "Account $username is currently locked due to credential check. Proceed to unlock via AD!"
    }
}

