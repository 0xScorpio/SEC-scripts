Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [3]
  ____) |
 |_____/ 

_____________________________________________________________
[SEC3] Tags and moves user/computer objects into disabled OU
_____________________________________________________________

"@ -ForegroundColor Cyan

#########################################################################################


################## FUNCTIONS TO CHECK IF ACCOUNTS EXIST ##################

# Function to check if a user exists
function CheckUserExists {
    param(
        [string]$userName
    )
    $user = Get-ADUser -Filter { SamAccountName -eq $userName }
    if ($user -eq $null) {
        Write-Host "User '$userName' does not exist."
        return $false
    }
    return $true
}

# Function to check if a computer exists
function CheckComputerExists {
    param(
        [string]$computerName
    )
    $computer = Get-ADComputer -Filter { Name -eq $computerName }
    if ($computer -eq $null) {
        Write-Host "Computer '$computerName' does not exist."
        return $false
    }
    return $true
}

# Function to check if a service account (user) exists
function CheckSvcExists {
    param(
        [string]$svcName
    )
    $service = Get-ADUser -Filter { SamAccountName -eq $svcName }
    if ($service -eq $null) {
        Write-Host "Service Account '$service' does not exist."
        return $false
    }
    return $true
}

# Function to check if external contractor account (user) exists
function CheckExtExists {
    param(
        [string]$extName
    )
    $external = Get-ADUser -Filter { SamAccountName -eq $extName}
    if ($external -eq $null) {
        Write-Host "External Contractor Account '$external' does not exist."
        return $false
    }
    return $true
}


############ FUNCTIONS TO MOVE ACCOUNTS TO THEIR CORRESPONDING OU PATHS ############
$currentDate = Get-Date
$sec3Tag = "[SEC3] $currentDate"

# Function to move user to disabled OU
function MoveUserToDisabledOU {
    param(
        [string]$userName
    )
    $user = Get-ADUser -Identity $userName -Properties SamAccountName, DistinguishedName, PasswordLastSet, LastLogonDate, Description, Enabled
    $disabledOU = "DISABLED-OU-FOR-USERS" ##### EDIT ####

    # Display user information
    Write-Host "User Information:"
    $user | Select-Object SamAccountName, DistinguishedName, PasswordLastSet, LastLogonDate, Description, Enabled
    $currentDescriptionuser = $user.Description
    $newDescriptionuser = "$sec3Tag | $currentDescriptionuser"

    # Prompt user to confirm
    $confirmation = Read-Host "Do you want to move user '$userName' to the disabled objects OU? (yes/no)"
    if ($confirmation -eq "yes") {
        # Move user to disabled objects OU
        Set-ADUser -Identity $user.SamAccountName -Description $newDescriptionuser
        Move-ADObject -Identity $user.DistinguishedName -TargetPath $disabledOU
        Write-Host "User '$userName' has been moved to the disabled objects OU."

        # Get the new OU information
        $newOU = Get-ADUser -Identity $userName | Select-Object DistinguishedName
        Write-Host "New OU Information:"
        $newOU
    } else {
        Write-Host "User '$userName' will not be moved to the disabled objects OU."
    }
}

# Function to move computer to disabled OU
function MoveComputerToDisabledOU {
    param(
        [string]$computerName
    )
    $computer = Get-ADComputer -Identity $computerName -Properties SamAccountName, DistinguishedName, LastLogonDate, Description, Enabled
    $disabledOU = "DISABLED-OU-FOR-COMPUTERS" #### EDIT ####

    # Display computer information
    Write-Host "Computer Information:"
    $computer | Select-Object SamAccountName, DistinguishedName, Description, Enabled, LastLogonDate
    $currentDescriptioncomp = $computer.Description
    $newDescriptioncomp = "$sec3Tag | $currentDescriptioncomp"

    # Prompt user to confirm
    $confirmation = Read-Host "Do you want to move computer '$computerName' to the disabled computers OU? (yes/no)"
    if ($confirmation -eq "yes") {
        # Move computer to disabled computers OU
        Set-ADComputer -Identity $computer.SamAccountName -Description $newDescriptioncomp
        Move-ADObject -Identity $computer.DistinguishedName -TargetPath $disabledOU
        Write-Host "Computer '$computerName' has been moved to the disabled computers OU."

        # Get the new OU information
        $newOU = Get-ADComputer -Identity $computerName | Select-Object DistinguishedName
        Write-Host "New OU Information:"
        $newOU
    } else {
        Write-Host "Computer '$computerName' will not be moved to the disabled computers OU."
    }
}

# Function to move service accounts to disabled OU
function MoveSvcToDisabledOU {
    param(
        [string]$svcName
    )
    $serviceaccount = Get-ADUser -Identity $svcName -Properties SamAccountName, DistinguishedName, PasswordLastSet, LastLogonDate, Description, Enabled
    $disabledOUsvc = "DISABLED-OU-FOR-SERVICEACCOUNTS" #### EDIT ####

    # Display service account information
    Write-Host "Service Account Information:"
    $serviceaccount | Select-Object SamAccountName, DistinguishedName, PasswordLastSet, LastLogonDate, Description, Enabled
    $currentDescriptionsvc = $serviceaccount.Description
    $newDescriptionsvc = "$sec3Tag | $currentDescriptionsvc"

    # Prompt user to confirm
    $confirmation = Read-Host "Do you want to move service account '$svcName' to the disabled objects OU? (yes/no)"
    if ($confirmation -eq "yes") {
        # Move service account(s) to disabled objects OU
        Set-ADUser -Identity $serviceaccount.SamAccountName -Description $newDescriptionsvc
        Move-ADObject -Identity $serviceaccount.DistinguishedName -TargetPath $disabledOUsvc
        Write-Host "Service account '$svcName' has been moved to the disabled objects OU."

        # Get the new OU information
        $newOU = Get-ADUser -Identity $svcName | Select-Object DistinguishedName
        Write-Host "New OU Information:"
        $newOU
    } else {
        Write-Host "Service account '$svcName' will not be moved to the disabled objects OU."
    }
}

# Function to move external contractor accounts to disabled OU
function MoveExtToDisabledOU {
    param(
        [string]$extName
    )
    $externalcontractor = Get-ADUser -Identity $extName -Properties SamAccountName, DistinguishedName, PasswordLastSet, LastLogonDate, Description, Enabled
    $disabledOUext = "DISABLED-OU-FOR-EXTERNALCONTRACTORS" #### EDIT ####
    $currentDescriptionexternal = $externalcontractor.Description
    $newDescriptionexternal = "$sec3Tag | $currentDescriptionexternal"

    # Display user information
    Write-Host "User Information:"
    $externalcontractor | Select-Object SamAccountName, DistinguishedName, PasswordLastSet, LastLogonDate, Description, Enabled

    # Prompt user to confirm
    $confirmation = Read-Host "Do you want to move external contractor '$extName' to the disabled objects OU? (yes/no)"
    if ($confirmation -eq "yes") {
        # Move user to disabled objects OU
        Set-ADUser -Identity $externalcontractor.SamAccountName -Description $newDescriptionexternal
        Move-ADObject -Identity $externalcontractor.DistinguishedName -TargetPath $disabledOUext
        Write-Host "External contractor '$extName' has been moved to the disabled objects OU."

        # Get the new OU information
        $newOU = Get-ADUser -Identity $extName | Select-Object DistinguishedName
        Write-Host "New OU Information:"
        $newOU
    } else {
        Write-Host "User '$extName' will not be moved to the disabled objects OU."
    }
}


############################# Main script ##################################
$objectType = Read-Host "Are you moving a user, service account, external contractor or computer object? (user/svc/ext/computer)"

if ($objectType -eq "user") {
    $objects = Read-Host "Enter the username(s), separated by spaces"
    $usernames = $objects -split " "
    
    foreach ($username in $usernames) {
        if (CheckUserExists -userName $username) {
            MoveUserToDisabledOU -userName $username
        }
    }
} elseif ($objectType -eq "computer") {
    $objects = Read-Host "Enter the computer name(s), separated by spaces"
    $computerNames = $objects -split " "
    
    foreach ($computerName in $computerNames) {
        if (CheckComputerExists -computerName $computerName) {
            MoveComputerToDisabledOU -computerName $computerName
        }
    }
} elseif ($objectType -eq "svc") {
    $objects = Read-Host "Enter the service account(s), separated by spaces"
    $svcs = $objects -split " "

    foreach ($svc in $svcs) {
        if (CheckSvcExists -svcName $svc) {
            MoveSvcToDisabledOU -svcName $svc
        }
    }
} elseif ($objectType -eq "ext") {
    $objects = Read-Host "Enter the external contractor account(s), separated by spaces"
    $exts = $objects -split " "

    foreach ($ext in $exts) {
        if (CheckExtExists -extName $ext) {
            MoveExtToDisabledOU -extName $ext
        }
    }
}