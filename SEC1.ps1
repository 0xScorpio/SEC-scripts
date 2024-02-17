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

function TagObjects {
    param (
        [string]$ObjectType,
        [string]$OUPath,
        [int]$DayThreshold,
        [datetime]$CurrentDate
    )

    try {
        if ($ObjectType -eq "computer") {
            $objects = Get-ADComputer -Filter * -SearchBase $OUPath -SearchScope Subtree -Properties SamAccountName, LastLogonDate, Description, Comment, PasswordLastSet, PasswordNeverExpires
        } elseif ($ObjectType -eq "user") {
            $objects = Get-ADUser -Filter * -SearchBase $OUPath -SearchScope Subtree -Properties SamAccountName, LastLogonDate, Description, Comment, PasswordLastSet, PasswordNeverExpires
        } else {
            throw "Invalid object type specified."
        }

        foreach ($object in $objects) {
            $inactivedays = ($CurrentDate - $object.LastLogonDate).Days
            $lastlog = $object.LastLogonDate.ToString('MM/dd/yyyy [HH:mm tt]')

            $existingDescription = $object.Description
            $existingComment = $object.Comment
            $pls = $object.PasswordLastSet
            $pne = $object.PasswordNeverExpires

            if ($inactivedays -ge $DayThreshold) {
                $newDescription = "[SEC1] Edited: $CurrentDate INACTIVE:$inactivedays LastLog: $lastlog PwdSet: $pls PwdNExp: $pne || "
                $latestSEC1 = $existingDescription -replace ".*||", $newDescription

                # Append the new description to the Comment attribute
                $newComment = "$newDescription | $existingComment"
                Set-ADObject -Identity $object.SamAccountName -Replace @{Comment=$newComment}
                # Update the Description attribute
                Set-ADObject -Identity $object -Description $newDescription

                Write-Host "Updated/appended 'Comment' attribute for $($object.SamAccountName)"
            }
        }
    } catch {
        Write-Host "Error: $_"
    }
}

# Validate and sanitize input parameters
if (-not ($OUPath -match '^OU=.*') -or -not (Test-Path -Path $OUPath -PathType Container)) {
    Write-Host "Invalid OU path specified."
    return
}

if ($dayThreshold_SEC1 -le 0) {
    Write-Host "Invalid day threshold specified."
    return
}

Write-Host "[SEC1] is about to apply tags unto the following OU path with the current threshold:"
Write-Host ""
Write-Host "$OUPath" -ForegroundColor Yellow
Write-Host ""
Write-Host "Threshold: $dayThreshold_SEC1 days" -ForegroundColor Yellow
Write-Host ""
$userChoice = Read-Host "Tagging means updating the description attribute. What object type are we tagging? (user/computer)"

$currentDate = Get-Date

if ($userChoice -eq "computer" -or $userChoice -eq "user") {
    TagObjects -ObjectType $userChoice -OUPath $OUPath_SEC1 -DayThreshold $dayThreshold_SEC1 -CurrentDate $currentDate
} else {
    Write-Host "Invalid object type specified."
}
