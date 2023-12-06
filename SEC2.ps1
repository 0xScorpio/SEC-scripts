Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [2]
  ____) |
 |_____/ 

_________________________________________________________________
[SEC2] disables user/computer accounts based on cautionary checks
_________________________________________________________________

"@ -ForegroundColor Cyan

#########################################################################################

$currentDate = Get-Date

## Prompt for user input
$accountType = Read-Host "What type of account(s) are we reviewing? (user/computer)"

if ($accountType -eq "user") {
    ######################## USER / SERVICE / EXT-CONTRACTOR ACCOUNTS #########################
    $userAccounts = Read-Host "Enter the user/service account(s) for review (separated by spaces)"
    $userList = $userAccounts -split ' '    
        
    foreach ($userAccount in $userList) {
        ## Check if the user account is currently locked/disabled
        $user = Get-ADUser -Identity $userAccount -Properties SamAccountName, UserPrincipalName, Enabled, LastLogonDate, PasswordLastSet, Description, DistinguishedName    

        ## Check if the user account EXISTS
        if ($user -eq $null) {
            Write-Host ""
            Write-Host "User account '$userAccount' not found."
            Write-Host ""
            continue
        }   

        ## Catch current description as a variable (Override checking)
        $currentDate = Get-Date
        $lastlogU = [datetime]::FromFileTime($user.LastLogon).ToString('dd/MM/yyyy [HH:mm]')
        $existingDescription = $user.Description
        $sec2Tag = "[SEC2] - Disabled (inactivity/decommission), LastLogon: $lastlogU, Edited: $currentDate"
        $newDescription = "$sec2Tag | $existingDescription"     

        ## Check if the user account is DISABLED
        if (-not $user.Enabled) {
            Write-Host ""
            Write-Host "User account '$userAccount' is already disabled."
            Write-Host ""
            Write-Host "Current description: $existingDescription"
            Write-Host "OU: $($user.DistinguishedName)"
            Write-Host ""
            Start-Sleep -Seconds 2
            continue
        }   

        ## If the user account isn't disabled, check for the last time the password was reset.
        $lastPasswordReset = $user.PasswordLastSet
        ## If the PasswordLastSet doesn't exist, inform and continue with rest of script.
        if ($lastPasswordReset -eq $null) {
            Write-Host ""
            Write-Host "Unable to retrieve the last password reset information for '$userAccount'."
            Write-Host "OU: $($user.DistinguishedName)"
            Write-Host ""
            continue
        }
        ## Print out information regarding PasswordLastSet attribute
        Write-Host ""
        Write-Host "Last password reset for '$userAccount': $lastPasswordReset"
        Write-Host "OU: $($user.DistinguishedName)" 
        Write-Host ""
        ## Print out last logon information as well

        Write-Host ""
        Write-Host "Last logon date for '$userAccount': $lastlogU (If it provides a 01/01/1601 - then there was a parsing error. Manually check on AD.)"
        Write-Host "OU: $($Computer.DistinguishedName)" 
        Write-Host ""

        ## Show the last time the password for the account was reset and provide prompt for whether the disable process should continue
        $confirmation = Read-Host "Do you want to proceed with disabling the account '$userAccount'? (yes/no)"  

        if ($confirmation -eq 'yes') {
            ## Disable account 
            Disable-ADAccount -Identity $userAccount
            ## Update description to SEC2
            Set-ADUser -Identity $userAccount -Description $newDescription
            Write-Host ""
            Write-Host "User account '$userAccount' has been disabled."
            Write-Host ""
        } else {
            Write-Host ""
            Write-Host "User account '$userAccount' was NOT disabled."
            Write-Host ""
        }
    }
} elseif ($accountType -eq "computer") {
    ######################## COMPUTER ACCOUNTS #########################
    $compAccounts = Read-Host "Enter the computer account(s) for review (separated by spaces)"
    $compList = $compAccounts -split ' '    

    foreach ($compAccount in $compList) {
        ## Check if the Computer Account is currently locked/disabled
        $Computer = Get-ADComputer -Identity $compAccount -Properties SamAccountName, UserPrincipalName, Enabled, LastLogon, LastLogonDate, PasswordLastSet, Description, DistinguishedName    

        ## Check if the Computer Account EXISTS
        if ($Computer -eq $null) {
            Write-Host ""
            Write-Host "Computer account '$compAccount' not found."
            Write-Host ""
            continue
        }   

        ## Catch current description as a variable (Override checking)
        $currentDateC = Get-Date
        $lastlog = [datetime]::FromFileTime($Computer.LastLogon).ToString('dd/MM/yyyy [HH:mm]')
        $sec2Tag = "[SEC2] Disabled (inactivity/decommission), LastLogon: $lastlog, Edited: $currentDateC"
        $existingDescriptionC = $Computer.Description
        $newDescriptionC = "$sec2Tag | $existingDescriptionC"     

        ## Check if the Computer Account is DISABLED
        if (-not $Computer.Enabled) {
            Write-Host ""
            Write-Host "Computer Account '$compAccount' is already disabled."
            Write-Host ""
            Write-Host "Current description: $existingDescription"
            Write-Host "OU: $($Computer.DistinguishedName)"
            Write-Host ""
            Start-Sleep -Seconds 2
            continue
        }   

        ## If the Computer Account isn't disabled, check for the last time the computer was logged on to.
        ## If the PasswordLastSet doesn't exist, inform and continue with rest of script.
        if ($lastPasswordResetC -eq $null) {
            Write-Host ""
            Write-Host "Unable to retrieve the last password reset information for '$compAccount'."
            Write-Host "OU: $($Computer.DistinguishedName)"
            Write-Host ""
            continue
        }
        Write-Host ""
        Write-Host "Last logon date for '$compAccount': $lastlog"
        Write-Host "OU: $($Computer.DistinguishedName)" 
        Write-Host ""

        ## Show the last time the password for the account was reset and provide prompt for whether the disable process should continue
        $confirmation = Read-Host "Do you want to proceed with disabling the account '$compAccount'? (yes/no)"  

        if ($confirmation -eq 'yes') {
            ## Disable account 
            Disable-ADAccount -Identity $compAccount
            ## Update description to SEC2
            Set-ADComputer -Identity $compAccount -Description $newDescriptionC
            Write-Host ""
            Write-Host "Computer Account '$compAccount' has been disabled."
            Write-Host ""
        } else {
            Write-Host ""
            Write-Host "Computer Account '$compAccount' was NOT disabled."
            Write-Host ""
        }
    }

} else {
    Write-Host ""
    Write-Host "Invalid input placed: $accountType"
    Write-Host "Exiting script..."
    Write-Host ""
    exit
}
