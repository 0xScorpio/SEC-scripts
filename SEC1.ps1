## [SEC1] TAGS on description - Computer inactivity and last logon ##

Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [1]
  ____) |
 |_____/ 

__________________________________________________________________________
[SEC1] tags all USER or COMPUTER objects, based on number of days inactive
__________________________________________________________________________

"@ -ForegroundColor Cyan


############## VARIABLES TO CHANGE ################
$OUPath = ""
$dayThreshold = 70
###################################################

$currentDate = Get-Date

$userChoice = Read-Host "Tagging means updating the description attribute. What object type are we tagging? (user/computer)"

if ($userChoice -eq "computer") {
    # Tag Computer objects with [SEC1] depending on dayThreshold variable
    $comps = Get-ADComputer -Filter * -SearchBase $OUPath -SearchScope Subtree -Properties SamAccountName, LastLogonDate, LastLogon, Description

    foreach ($comp in $comps) {
        $inactivedays = ($currentDate - $comp.LastLogonDate).Days
        $lastlog = [datetime]::FromFileTime($comp.LastLogon).ToString('dd/MM/yyyy [HH:mm]')

        $existingDescription = $comp.Description

        if ($inactivedays -ge $dayThreshold) {
            $newDescription = "[SEC1] Inactive: $inactivedays days. LastLogon: $lastlog Edited: $currentDate"

            # If an existing description exists, either print or append the new information
            if ($existingDescription) {
                Write-Host ""
                Write-Host "EXISTING DESCRIPTION EXISTS FOR" $comp.SamAccountName
                Write-Host ""
                ## Uncomment this if you don't want to overwrite the current description
                $newDescription = "$newDescription | $existingDescription"
            }

        Set-ADComputer -Identity $comp.SamAccountName -Description $newDescription
        Write-Host "Updated description for" $comp.SamAccountName

        }
    }
} elseif ($userChoice -eq "user") {
    # Tag User objects with [SEC1] depending on dayThreshold variable

    # Pull all users within a search scope
    $users = Get-ADUser -Filter * -SearchBase $OUPath -SearchScope Subtree -Properties SamAccountName, LastLogonDate, LastLogon, Description

    foreach ($user in $users) {
        $inactivedaysU = ($currentDate - $user.LastLogonDate).Days
        $lastLogU = [datetime]::FromFileTime($user.LastLogon).ToString('dd/MM/yyy [HH:mm]')

        $existingDescriptionU = $user.Description

        if ($inactivedays -ge $dayThreshold) {
            $newDescriptionU = "[SEC1] Inactive: $inactivedaysU days. LastLogon: $lastlogU Edited: $currentDate"

            # If an existing description exists, either print or append the new information
            if ($existingDescriptionU) {
                Write-Host ""
                Write-Host "EXISTING DESCRIPTION EXISTS FOR" $user.SamAccountName
                Write-Host ""
                $newDescriptionU = "$newDescriptionU | $existingDescriptionU"
            }

            Set-ADUser -Identity $user.SamAccountName -Description $newDescriptionU
            Write-Host "Updated description for" $user.SamAccountName
        }
    }
}


