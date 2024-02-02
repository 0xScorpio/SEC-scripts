## [SEC1] TAGS on description - Computers/Users inactivity, last logon ##

Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [1]
  ____) |
 |_____/ 

__________________________________________________________________________
[SEC1] TAGS all user or computer objects, based on number of days inactive
__________________________________________________________________________

"@ -ForegroundColor Cyan

############## VARIABLES TO CHANGE ################
$OUPath = "OU-PATH"
$dayThreshold = 70
# This is for converting Greek time signatures to AM or PM
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
###################################################

$currentDate = Get-Date

Write-Host "[SEC1] is about to apply tags unto the following OU path with the current threshold:"
Write-Host ""
Write-Host "$OUPath" -ForegroundColor Yellow
Write-Host ""
Write-Host "Threshold: $dayThreshold days" -ForegroundColor Red
Write-Host ""
$userChoice = Read-Host "Tagging means updating the description attribute. What object type are we tagging? (user/computer)"

if ($userChoice -eq "computer") {
    # Tag Computer objects with [SEC1] depending on dayThreshold variable
    $comps = Get-ADComputer -Filter * -SearchBase $OUPath -SearchScope Subtree -Properties SamAccountName, LastLogonDate, Description, Comment, PasswordLastSet, PasswordNeverExpires

    foreach ($comp in $comps) {
        $inactivedays = ($currentDate - $comp.LastLogonDate).Days
        $lastlog = $comp.LastLogonDate.ToString('dd/MM/yyyy [HH:mm tt]')

        $existingDescription = $comp.Description
        $existingComment = $comp.Comment
        $pls = $comp.PasswordLastSet
        $pne = $comp.PasswordNeverExpires

        if ($inactivedays -ge $dayThreshold) {
            $newDescription = "[SEC1] Edited: $currentDate INACTIVE: $inactivedays days. LastLogon: $lastlog PwdLastSet: $pls PwdNeverExpires: $pne ----"
            $latestSEC1 = $existingDescription -replace ".*----", $newDescription

            # Append the new description to the Comment attribute
            $newComment = "$newDescription | $existingComment"
            Set-ADComputer -Identity $comp.SamAccountName -Replace @{Comment=$newComment}
            Write-Host "Updated and appended security comment log for $($comp.SamAccountName)"

            # Check if [SEC1] already exists in the description and override it
            if ($existingDescription -like "*[SEC1]*") {
                $latestSEC1
                Write-Host "UPDATED current [SEC1] description to latest changes."
            } else {
                Set-ADComputer -Identity $comp -Description $newDescription
                Write-Host "[SEC1] description does NOT exist! Adding new [SEC1] description!"
            }
        }
    }
} elseif ($userChoice -eq "user") {
    # Tag User objects with [SEC1] depending on dayThreshold variable

    # Pull all users within a search scope
    $users = Get-ADUser -Filter * -SearchBase $OUPath -SearchScope Subtree -Properties SamAccountName, LastLogonDate, Description, Comment, PasswordLastSet, PasswordNeverExpires

    foreach ($user in $users) {
        $inactivedaysU = ($currentDate - $user.LastLogonDate).Days
        $lastlogU = $user.LastLogonDate.ToString('dd/MM/yyyy [HH:mm tt]')

        $existingDescriptionU = $user.Description
        $existingCommentU = $user.Comment
        $plsu = $user.PasswordLastSet
        $pneu = $user.PasswordNeverExpires

        if ($inactivedaysU -ge $dayThreshold) {
            $newDescriptionU = "[SEC1] Edited: $currentDate INACTIVE: $inactivedaysU days. LastLogon: $lastlogU PwdLastSet: $plsu PwdNeverExpires: $pneu ----"
            $latestSEC1U = $existingDescriptionU -replace ".*----", $newDescriptionU

            # Append the new description to the Comment attribute
            $newCommentU = "$newDescriptionU | $existingCommentU"
            Set-ADUser -Identity $user.SamAccountName -Replace @{Comment=$newCommentU}
            Write-Host "Updated and appended security comment log for $($user.SamAccountName)"

            # Check if [SEC1] already exists in the description and override it
            if ($existingDescriptionU -like "*[SEC1]*") {
                $latestSEC1U
                Write-Host "UPDATED current [SEC1] description to latest changes."
            } else {
                Set-ADUser -Identity $user -Description $newDescriptionU
                Write-Host "[SEC1] description does NOT exist! Adding new [SEC1] description!"
            }
        }
    }
}
