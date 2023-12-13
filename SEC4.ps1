Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [4]
  ____) |
 |_____/ 

____________________________________________________
[SEC4] disables user account due to CREDENTIAL LEAK!
____________________________________________________

"@ -ForegroundColor Cyan

#########################################################################################

## Prompt for user input
$userAccounts = Read-Host "Enter the user account(s) whose credentials have been leaked (separated by spaces)"
$userList = $userAccounts -split ' '

foreach ($userAccount in $userList) {
    ## Check if the user account is currently locked/disabled
    $user = Get-ADUser -Identity $userAccount -Properties SamAccountName, UserPrincipalName, Enabled, LastLogonDate, PasswordLastSet, Description, DistinguishedName, Comment

    if ($user -eq $null) {
        Write-Host "User account '$userAccount' not found."
        continue
    }

    if (-not $user.Enabled) {
        Write-Host "User account '$userAccount' is already disabled."
        Write-Host "Current description: $($user.Description)"
        Write-Host "OU: $($user.DistinguishedName)"
        Start-Sleep -Seconds 3
        continue
    }

    ## If the user account isn't disabled, check for the last time the password was reset.
    $lastPasswordReset = $user.PasswordLastSet

    if ($lastPasswordReset -eq $null) {
        Write-Host "Unable to retrieve the last password reset information for '$userAccount'."
        Write-Host "OU: $($user.DistinguishedName)"
        continue
    }

    Write-Host "Last password reset for '$userAccount': $lastPasswordReset"
    Write-Host "OU: $($user.DistinguishedName)"

    ## Show the last time the password for the account was reset and provide prompt to ask whether the disable process should continue
    $confirmation = Read-Host "Do you want to proceed with disabling the account '$userAccount'? (yes/no)"

    if ($confirmation -eq 'yes') {
        ## Disable account and update description to SEC4
        $currentDesc = $($user.Description)
        $currentComment = $($user.Comment)
        $sec4Tag = "[SEC4] CREDENTIAL LEAK! Password reset required. Edited: $(Get-Date)"
        $newDesc = "$sec4Tag | $currentDesc"
        $newComment = "$sec4Tag | $currentComment"

        Disable-ADAccount -Identity $userAccount
        Set-ADUser -Identity $userAccount -Replace @{Comment=$newComment}
        Set-ADUser -Identity $userAccount -Description $newDesc
        Write-Host "User account '$userAccount' has been disabled."
    } else {
        Write-Host "User account '$userAccount' was not disabled."
    }
}
