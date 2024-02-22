### Written by 0xScorpio -----> vnoproject.com ###
### Git Repo: github.com/0xScorpio/SEC-Scripts ###

Write-Host ""
Write-Host @"

 :'######::'########::'######::::::::'##:::::'#####:::::'#####:
'##... ##: ##.....::'##... ##:::::'####::::'##.. ##:::'##.. ##::
 ##:::..:: ##::::::: ##:::..::::::.. ##:::'##:::: ##:'##:::: ##:
. ######:: ######::: ##::::::::::::: ##::: ##:::: ##: ##:::: ##:
:..... ##: ##...:::: ##::::::::::::: ##::: ##:::: ##: ##:::: ##:
'##::: ##: ##::::::: ##::: ##::::::: ##:::. ##:: ##::. ##:: ##::
. ######:: ########:. ######::::::'######::. #####::::. #####:::
:......:::........:::......:::::::......::::.....::::::.....::: 

 _________________________________________________________________
|                                                                 |
| This GOD-like script does it all - Pick your poison carefully!  |
|                                                                 |
|_________________________________________________________________|

If any 'tagging' is involved within the script, it will ALWAYS tag
the 'Comments' attribute within Attribute Editor, to keep track of
historical updates to an object for logging purposes.

                                                ~ John / 0xScorpio

"@ -ForegroundColor Cyan

###################################################################################
#################################### VARIABLES ####################################
###################################################################################

# Static Variables - DO NOT CHANGE!

[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
$currentDate = Get-Date
$currentDateFormatted = Get-Date -Format "ddMMyyyy"

#---------------------------------------------------------------------------------#

# Custom Variables - EDIT VARIABLES HERE!

# Due to some scripts sharing variables such as OU Paths, they've instead been
# separated to ensure no user error occurs when 'forgetting' to change the variable
# for usage on another script! Tread carefully!

#### SEC0 ####
$keywords_SEC0 = "[SEC1]", "[SEC2]"

#### SEC1 ####
$OUPath_SEC1 = "OU=123"
$dayThreshold_SEC1 = 70

#### SEC6 ####

#### SEC13 ####
$maxBadLogins_SEC13 = 1

#### SEC14 ####

#### SEC17 ####
$startTime_SEC17 = (Get-Date).AddHours(-24)

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

###################################################################################
#################################### BANNERS ######################################
###################################################################################

# Banner for SEC99
function Banner-SEC99 {
            Write-Host @"

'########::'##:::'##:'########::::'####:
 ##.... ##:. ##:'##:: ##.....::::: ####:
 ##:::: ##::. ####::: ##:::::::::: ####:
 ########::::. ##:::: ######::::::: ##::
 ##.... ##:::: ##:::: ##...::::::::..:::
 ##:::: ##:::: ##:::: ##::::::::::'####:
 ########::::: ##:::: ########:::: ####:
........::::::..:::::........:::::....::  
                                                                                                                     
"@ -ForegroundColor Cyan 

Sleep 1
Exit

}

# Banner for SEC0
function Banner-SEC0 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 0   ============================                            

Filters Active Directory for SEC code descriptions and exports results in CSV.
Export path is local to the working directory, therefore, if you run the script
on C:\Users\USER\Desktop\ , you'll find it on the corresponding user's desktop!

Attribute Tags: N/A

Prerequisite variables to edit:

[1] `$keywords_SEC0
____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC1
function Banner-SEC1 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 1   ============================ 

Tags User/Computer accounts based on the number of days inactive - on a specific
organizational unit. The default threshold of days allowed for inactivity is 70 days, 
though feel free to edit both OU Path and threshold days under 'Custom Variables'.

Attribute Tags: Description, Comment

Prerequisite variables to edit:

[1] '`$OUPath_SEC1'
[2] '`$dayThreshold_SEC1'
____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC2
function Banner-SEC2 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 2   ============================ 

Disables User/Computer account(s) and then tags them accordingly. Use [SEC0] if need
be, to collect a list of objects (ideally the ones that meet the requirements of [SEC1]
- inactive objects) and paste them here if multiple objects need to be disabled at once. 

REMEMBER! With ADSync forcing deletion precautions, there is a default threshold of 50 
object deletions per cycle --- you may only delete 50 objects every 30 minutes!

This may or may not be the exact cycle frequency depending on the configurations set
on your company's Azure AD Connect/ADSync - so make sure to check/inform IT first!

Attribute Tags: Description, Comment

Prerequisite variables to edit: N/A
____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC3
function Banner-SEC3 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 3   ============================ 

Moves User/Computer objects (including service accounts, external contractors) to 
their corresponding disabled OU path. It checks to ensure all use-cases pass before
moving any object:

- Where is the object currently?
- Is the object already disabled?
- Prompts the user for permission to move the object.
- Only moves objects if they are disabled and given permission by the user.

Attribute Tags: Comment

Prerequisite variables to edit: N/A
____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC4
function Banner-SEC4 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 4   ============================     

If there is a CREDENTIAL LEAK for a specific user account (done by the Cybersecurity
department's Threat Intel), run [SEC4] to disable and tag the account accordingly!

*Before re-enabling the account for the user, they MUST reset their password first!

Attribute Tags: Description, Comment

Prerequisite variables to edit: N/A

____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC5
function Banner-SEC5 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 5   ============================    

JUST-IN-TIME! 

Attribute Tags: Description, Comment

Prerequisite variables to edit: N/A
____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC6
function Banner-SEC6 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 6   ============================ 

WARNING!!! Be careful with this script as it literally DELETES User/Computer objects!
By default, a normal delete is technically a soft-delete: wiped from AD but stored
for 30 days based on the configured recovery threshold.

Bulk deletion is possible (you can place multiple objects separated by spaces) but it 
will still request for permission from the user after printing all the information of 
a each User/Computer account one by one!

This script will also initially check for inactive days of an object (even if you've 
already used [SEC1]) as a precaution and ensure it meets the inactive day threshold
as well, before deleting it from AD. 

Default threshold is 100 days. 

[SEC1] checks for 70 days - [SEC6] adds a 30 day buffer for recovery instances.

Attribute Tags: N/A

Prerequisite variables to edit:

[1] `$OUPath_SEC6
[2] `$inactivity_SEC6
____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC7
function Banner-SEC7 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 7   ============================   

COMING SOON!

Attribute Tags: N/A

Prerequisite variables to edit: N/A

____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC8
function Banner-SEC8 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 8   ============================ 

COMING SOON!

Attribute Tags: N/A

Prerequisite variables to edit: N/A

____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC9
function Banner-SEC9 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 9   ============================ 

COMING SOON!

Attribute Tags: N/A

Prerequisite variables to edit: N/A

____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC10
function Banner-SEC10 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 10   ============================ 

COMING SOON!

Attribute Tags: N/A

Prerequisite variables to edit: N/A

____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC11
function Banner-SEC11 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 11   ============================ 

Pulls information regarding SMB, TLS, Hashes and Ciphers through the Registry Editor. 
Specifically, this script checks the following paths:

- HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
- HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols
- HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes
- HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers

# Fully hardened systems include:
- SMBv2, TLS 1.2, SHA256/384/512 and AES standards only.

# For legacy best practices:
- SMBv2, TLS 1.0/1.1/1.2, SHA/MD5/SHA256/384/512 and 3DES/AES standards only.

Any protocol set below the standards mentioned assumes an internal risky server that 
needs to be monitored carefully and is most likely due to dependency incompatibility 
issues with older server versions or legacy system applications.


Attribute Tags: N/A

Prerequisite variables to edit: N/A 
____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC12
function Banner-SEC12 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 12   ============================ 

Did someone / something log in to a server via RDP and possibly did something suspicious?
Well, this is the script for you! Checks for recent events via Event 4624.
Feel free to edit the -MaxEvents parameter to your chosen number of events.

Attribute Tags: N/A

Prerequisite variables to edit: N/A
____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC13
function Banner-SEC13 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 13   ============================ 

The official credential verifier!

First, it will check to ensure that the account you want to validate is not currently
locked out or is about to get locked out if a credential check fails!

Default `$maxBadLogins is set to 1.

Attribute Tags: N/A

Prerequisite variables to edit: N/A
____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC14
function Banner-SEC14 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 14   ============================ 

COMING SOON!

Attribute Tags: Description, Comment

Prerequisite variables to edit:

[1] '`$keywords'
____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC15
function Banner-SEC15 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 15   ============================ 

Displays the important information for User/Computer objects and then prompts for
edits if required. 

Attribute Tags: N/A

Prerequisite variables to edit: N/A
____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC16
function Banner-SEC16 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 16   ============================ 

Run this on a domain controller in order to sift through Event Viewer for User events
that caused a user to be locked out of their account. Useful for clearing up sessions!

Attribute Tags: N/A

Prerequisite variables to edit: N/A
____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

# Banner for SEC17
function Banner-SEC17 {
            Write-Host @"
____________________________________________________________________________________

============================   SECURITY CODE 17   ============================   

Checks all the disabled/enabled object events in the past X hours.
Customize the Start Time variable accordingly. Default start time is 24 hours.

Attribute Tags: N/A

Prerequisite variables to edit: N/A
____________________________________________________________________________________
"@ -ForegroundColor Cyan 
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

###################################################################################
#################################### FUNCTIONS ####################################
###################################################################################

# Initial menu choice
function Get-Choice {
    Sleep 1
 Write-Host @"

------------------    Security Scripts Menu    ------------------

=================================================================
| Security Code |                  Description                  |
=================================================================
|     SEC0      | Search/Filters Active Directory by SEC code   |
|     SEC1      | Tags inactive User/Computer accounts          | 
|     SEC2      | Disables User/Computer accounts               |
|     SEC3      | Moves User/Computer accounts to Disabled OU   |
|     SEC4      | CREDENTIAL LEAK - Disables and tags account   |
|     SEC5      | Just-In-Time Access for User/Service accounts |
|     SEC6      |                     TBD                       |
|     SEC7      |                     TBD                       |
|     SEC8      |                     TBD                       |
|     SEC9      |                     TBD                       |
|     SEC10     |                     TBD                       |
|     SEC11     | Checks SMB/TLS/Hashes from registry editor    |
|     SEC12     | Checks local RDP logon sessions on a server   |
|     SEC13     | Check credential - check thresholds/lockouts  |
|     SEC14     |                     TBD                       |
|     SEC15     | Pull and/or Edit User/Computer information    |
|     SEC16     | Checks for locked-out user events on DC       |
|     SEC17     | Checks logs on enabled/disabled object events |
================================================================= 

                    SEC99   =   exit script!

"@ -ForegroundColor Yellow
    Write-Host ""
    $choice = Read-Host "Enter a SEC script number to run (e.g. 13) or exit (99)"
    Write-Host ""
    return $choice
}

# Run corresponding banner
function Run-Banner([int] $securityBanner) {
    $bannerFunctionName = "Banner-SEC$securityBanner"
    if (Test-Path function:\$bannerFunctionName) {
        & $bannerFunctionName
    } else {
        Write-Host ""
        Write-Host "Security banner for SEC$securityBanner not found. Exiting program..." -ForegroundColor Red
        Write-Host ""
        Sleep 1
        Banner-SEC99
        Sleep1
        Exit
    }
}

# Check prerequisites
function Show-Prerequisites([int] $requisite) {
    switch ($requisite) {
        
        '0' {
            Write-Host ""
            Write-Host "The following variable values are being executed with the script:"
            Write-Host ""
            Write-Host "`$keywords_SEC0: $keywords" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "If you need to change any variables, stop the script [Ctrl+C]"
            Write-Host "and change those stated variables within the VARIABLES section!"
            Write-Host ""
        }

        '1' {
            Write-Host ""
            Write-Host "The following variable values are being executed with the script:"
            Write-Host ""
            Write-Host "`$OUPath_SEC1: $OUPath_SEC1" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "`$dayThreshold_SEC1: $dayThreshold_SEC1" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "If you need to change any variables, stop the script [Ctrl+C]"
            Write-Host "and change those stated variables within the VARIABLES section!"
            Write-Host ""
        }
            ##############     ADD  MORE      ##################
        'default' {
            Write-Host ""
            Write-Host "No pre-requisite variables required!"
            Write-Host ""
        }
    }
}

# Run corresponding security code script when called
function Run-SecurityCode([int] $securityCode) {
    $securityScriptName = "Init-SEC$securityCode"
    if (Test-Path function:\$securityScriptName) {
        & $securityScriptName
    } else {
        Write-Host ""
        Write-Host "Security code script Init-SEC$securityCode not found. Exiting..." -ForegroundColor Red
        Write-Host ""
        Sleep 1
        Banner-SEC99
        Sleep1
        Exit
    }
}

###################################################################################
######################## INITIALIZE SECURITY CODES ################################
###################################################################################

function Init-SEC0 {

    # Check if $keywords_SEC0 is a non-empty string ---> input validation
    if (-not [string]::IsNullOrEmpty($keywords_SEC0) -and $keywords_SEC0 -is [string]) {

        # Create an array to store individual filter conditions
        $filterConditions = foreach ($keyword in $keywords_SEC0) {
            "Description -like '*$keyword*'"
        }

        # Combine filter conditions
        $filterExpression = ($filterConditions -join " -or ")

        # Search for objects based on keywords in the description
        $objects = Get-ADObject -Filter $filterExpression -Properties SamAccountName, Description, DistinguishedName

        # Output the results to console and export to CSV file
        $objects | ForEach-Object {

            Write-Host "SAM Account Name: $($_.SamAccountName)"
            Write-Host "Description: $($_.Description)"
            Write-Host "DistinguishedName: $($_.DistinguishedName)"
            Write-Host "------------------------------------------------"

            # Output the object directly to pipeline
            [PSCustomObject]@{
                SamAccountName = $_.SamAccountName
                Description = $_.Description
                DistinguishedName = $_.DistinguishedName
            }

        } | Export-Csv -Path "SecurityCodeScan_$currentDateFormatted.csv" -NoTypeInformation

        Write-Host ""
        Write-Host "Data exported to 'SecurityCodeScan.csv_$currentDateFormatted' file!" -ForegroundColor Yellow
        Write-Host ""

    } else {

        Write-Host ""
        Write-Host "Keywords are either empty or not a string. Exiting the program..." -ForegroundColor Red
        Write-Host ""

    }

    Sleep 1
    Banner-SEC99
    Sleep1
    Exit

}

function Init-SEC1 {
    function TagObjects {
        param (
            [string]$ObjectType,
            [string]$OUPath,
            [int]$DayThreshold,
            [datetime]$CurrentDate
        )

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

            try {
                if ($inactivedays -ge $DayThreshold) {
                    $newDescription = "[SEC1] Edited: $CurrentDate INACTIVE:$inactivedays LastLog: $lastlog PwdSet: $pls PwdNExp: $pne || "
                    $latestSEC1 = $existingDescription -replace ".*||", $newDescription

                    # Append the new description to the Comment attribute
                    $newComment = "$newDescription | $existingComment"
                    Set-ADObject -Identity $object -Replace @{Comment=$newComment}
                    # Update the Description attribute
                    Set-ADObject -Identity $object -Description $newDescription

                    Write-Host "Updated/appended 'Comment' attribute for $($object.SamAccountName)"
                }
            } catch {
                # Added the stack-trace for debugging because I couldn't find what failed just by PSItem
                Write-Host "Error: [+] $_"
                Write-Host $_.ScriptStackTrace
                continue
            } 
        }
    }

    # Validate and sanitize input parameters
    if (-not ($OUPath_SEC1 -match '^OU=.*') -or -not ([adsi]::Exists("LDAP://$OUPath_SEC1"))) {
        Write-Host "Invalid OU path specified."
        return
    }

    if ($dayThreshold_SEC1 -le 0) {
        Write-Host "Invalid day threshold specified."
        return
    }

    Write-Host "[SEC1] is about to apply tags unto the following OU path with the current threshold:"
    Write-Host ""
    Write-Host "OU-Path: $OUPath_SEC1" -ForegroundColor Yellow
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

    Sleep 1
    Banner-SEC99
    Sleep1
    Exit
}

function Init-SEC2 {
    ## Prompt for user input
    $accountType = Read-Host "What type of account(s) are we reviewing? (user/computer)"

    if ($accountType -eq "user") {
        ######################## USER / SERVICE / EXT-CONTRACTOR ACCOUNTS #########################
        $userAccounts = Read-Host "Enter the user/service account(s) for review (separated by spaces)"
        $userList = $userAccounts -split ' '    
            
        foreach ($userAccount in $userList) {
            ## Check if the user account is currently locked/disabled
            $user = Get-ADUser -Identity $userAccount -Properties SamAccountName, UserPrincipalName, Enabled, LastLogonDate, PasswordLastSet, Description, DistinguishedName, Comment    

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
            $sec2Tag = "[SEC2] - Disabled (inactivity/decommission) $currentDate, LastLogon: $lastlogU, LastPasswordSet: $($user.PasswordLastSet)"
            $currentComment = $user.Comment
            $newComment = "$sec2Tag | $currentComment"
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
                ## Update description & comment attributes to SEC2
                Set-ADUser -Identity $userAccount -Replace @{Comment=$newComment}
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
            $Computer = Get-ADComputer -Identity $compAccount -Properties SamAccountName, UserPrincipalName, Enabled, LastLogon, LastLogonDate, Description, DistinguishedName    

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
            $sec2Tag = "[SEC2] Disabled (inactivity/decommission) $currentDateC, LastLogon: $lastlog"
            $existingDescriptionC = $Computer.Description
            $currentCommentC = $Computer.Comment
            $newCommentC = "$sec2Tag | $currentCommentC"
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

            ## Print relevant information
            Write-Host ""
            Write-Host "Last logon date for '$compAccount': $lastlog"
            Write-Host "OU: $($Computer.DistinguishedName)" 
            Write-Host ""

            ## Show the last time the password for the account was reset and provide prompt for whether the disable process should continue
            $confirmation = Read-Host "Do you want to proceed with disabling the account '$compAccount'? (yes/no)"  

            if ($confirmation -eq 'yes') {
                ## Disable account 
                Disable-ADAccount -Identity $compAccount
                ## Update description & comment attributes to SEC2
                Set-ADComputer -Identity $compAccount -Replace @{Comment=$newCommentC}
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
        
        Sleep 1
        Banner-SEC99
        Sleep1
        Exit
    }
}

function Init-SEC3 {
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
        $user = Get-ADUser -Identity $userName -Properties SamAccountName, DistinguishedName, PasswordLastSet, LastLogonDate, Description, Enabled, Comment
        $disabledOU = "DISABLED-OU-FOR-USERS" ##### EDIT ####

        # Display user information
        Write-Host "User Information:"
        $user | Select-Object SamAccountName, DistinguishedName, PasswordLastSet, LastLogonDate, Description, Enabled, Comment
        $currentCommentuser = $user.Comment
        $newCommentuser = "$sec3Tag | $currentCommentuser"

        # Prompt user to confirm
        $confirmation = Read-Host "Do you want to move user '$userName' to the disabled objects OU? (yes/no)"
        if ($confirmation -eq "yes") {
            # Move user to disabled objects OU
            Set-ADUser -Identity $user.SamAccountName -Replace @{Comment=$newCommentuser}
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
        $computer = Get-ADComputer -Identity $computerName -Properties SamAccountName, DistinguishedName, LastLogonDate, Description, Enabled, Comment
        $disabledOU = "DISABLED-OU-FOR-COMPUTERS" #### EDIT ####

        # Display computer information
        Write-Host "Computer Information:"
        $computer | Select-Object SamAccountName, DistinguishedName, Description, Enabled, LastLogonDate, Comment
        $currentCommentcomp = $computer.Comment
        $newCommentcomp = "$sec3Tag | $currentCommentcomp"

        # Prompt user to confirm
        $confirmation = Read-Host "Do you want to move computer '$computerName' to the disabled computers OU? (yes/no)"
        if ($confirmation -eq "yes") {
            # Move computer to disabled computers OU
            Set-ADComputer -Identity $computer.SamAccountName -Replace @{Comment=$newCommentcomp}
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
        $serviceaccount = Get-ADUser -Identity $svcName -Properties SamAccountName, DistinguishedName, PasswordLastSet, LastLogonDate, Description, Enabled, Comment
        $disabledOUsvc = "DISABLED-OU-FOR-SERVICEACCOUNTS" #### EDIT ####

        # Display service account information
        Write-Host "Service Account Information:"
        $serviceaccount | Select-Object SamAccountName, DistinguishedName, PasswordLastSet, LastLogonDate, Description, Enabled, Comment
        $currentCommentsvc = $serviceaccount.Comment
        $newCommentsvc = "$sec3Tag | $currentCommentsvc"

        # Prompt user to confirm
        $confirmation = Read-Host "Do you want to move service account '$svcName' to the disabled objects OU? (yes/no)"
        if ($confirmation -eq "yes") {
            # Move service account(s) to disabled objects OU
            Set-ADUser -Identity $serviceaccount.SamAccountName -Replace @{Comment=$newCommentsvc}
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
        $externalcontractor = Get-ADUser -Identity $extName -Properties SamAccountName, DistinguishedName, PasswordLastSet, LastLogonDate, Description, Enabled, Comment
        $disabledOUext = "DISABLED-OU-FOR-EXTERNALCONTRACTORS" #### EDIT ####
        $currentCommentexternal = $externalcontractor.Comment
        $newCommentexternal = "$sec3Tag | $currentCommentexternal"

        # Display user information
        Write-Host "User Information:"
        $externalcontractor | Select-Object SamAccountName, DistinguishedName, PasswordLastSet, LastLogonDate, Description, Enabled, Comment

        # Prompt user to confirm
        $confirmation = Read-Host "Do you want to move external contractor '$extName' to the disabled objects OU? (yes/no)"
        if ($confirmation -eq "yes") {
            # Move user to disabled objects OU
            Set-ADUser -Identity $externalcontractor.SamAccountName -Replace @{Comment=newCommentexternal}
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
}

function Init-SEC4 {
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
}

function Init-SEC5 {
    $sec5tag = "[SEC5] JIT Access (comment/info attribute for logs/details)"

    # Prompt user for the service account
    $serviceAccount = Read-Host "Enter the service account name"

    # Check if the service account exists
    $account = Get-ADUser -Identity $serviceAccount -Properties Enabled, Description, DistinguishedName, Comment -ErrorAction SilentlyContinue

    if (-not $account) {
        Write-Host ""
        Write-Host "Service account '$serviceAccount' not found."
        Write-Host ""
        Sleep 1
        Banner-SEC99
        Sleep1
        Exit
    }

    # Display account information
    Write-Host ""
    Write-Host "SamAccountName: $($account.SamAccountName)"
    Write-Host "Enabled: $($account.Enabled)"
    Write-Host "Description: $($account.Description)"
    Write-Host "Log History: $($account.Comment)"
    Write-Host ""
    Write-Host "OU Path: $($account.DistinguishedName)"
    Write-Host ""

    # Check if the account is tagged
    if ($account.Description -notmatch '\[SEC5\]') {
        Write-Host ""
        Write-Host "Account '$serviceAccount' needs to be tagged first with '$sec5tag'."
        Write-Host ""
        $promptForTag = Read-Host "Do you want to tag $serviceAccount as a JIT Access account? (yes/no)"
            if ($promptforTag -eq "yes") {
                if ($account.Description) {
                    $currentDescription = $account.Description
                    $newDescription = "$sec5tag | $currentDescription"
                    Set-ADUser -Identity $serviceAccount -Description $newDescription
                    Write-Host ""
                    Write-Host "Account '$serviceAccount' tagged with '$sec5tag'."
                    Write-Host ""
                } else {
                    Write-Host ""
                    Write-Host "No previously existing description. Proceeding to tag the account."
                    Write-Host ""
                    $newDescription = "$sec5tag"
                    Set-ADUser -Identity $serviceAccount -Description $newDescription
                }
            } else {
                Write-Host ""
                Write-Host "No tag placed. Account needs to be tagged before enabling/disabling!"
                Write-Host ""
            }
        Sleep 1
        Banner-SEC99
        Sleep1
        Exit
    }

    $promptChoice = Read-Host "Based on the account information displayed, here are your options: enable, disable, exit"

    if ($promptChoice -eq "enable") {
        if (-not $account.Enabled) {
            ########
            $currentCommentEnabled = $account.Comment
            $newCommentEnabled = "Enabled: $(Get-Date) | $currentCommentEnabled"
            Enable-ADAccount -Identity $serviceAccount
            Set-ADUser -Identity $serviceAccount -Replace @{Comment = $newCommentEnabled}
            Write-Host ""
            Write-Host "$serviceAccount has been enabled!"
            $checkE = Get-ADUser -Identity $serviceAccount -Properties Comment
            Write-Host "Logged on comment attribute: $($checkE.Comment)"
            Write-Host ""
        } else {
            Write-Host ""
            Write-Host "$serviceAccount is already enabled. Exiting script..."
            Write-Host ""
            Sleep 1
            Banner-SEC99
            Sleep1
            Exit
        }
    } elseif ($promptChoice -eq "disable") {
        # If account is already disabled, print and exit.
        if ($account.Enabled) {
            $currentCommentDisabled = $account.Comment
            $newCommentDisabled = "Disabled: $(Get-Date) | $currentCommentDisabled"
            Disable-ADAccount -Identity $serviceAccount
            Set-ADUser -Identity $serviceAccount -Replace @{Comment = $newCommentDisabled}
            Write-Host ""
            Write-Host "$serviceAccount has been disabled!"
            $checkD = Get-ADUser -Identity $serviceAccount -Properties Comment
            Write-Host "Logged on comment attribute: $($checkD.Comment)"
            Write-Host ""
        } else {
            Write-Host ""
            Write-Host "$serviceAccount is already disabled. Exiting script..."
            Write-Host ""
            Sleep 1
            Banner-SEC99
            Sleep1
            Exit
        }
    } elseif ($promptChoice -eq "exit") {
        exit
    } else {
        Write-Host ""
        Write-Host "You entered $promptChoice which is not a valid input! Exiting..."
        Write-Host ""
        Sleep 1
        Banner-SEC99
        Sleep1
        Exit
    }
}

function Init-SEC6 {
    Write-Host "COMING SOON!"
}

function Init-SEC7 {
    Write-Host "COMING SOON!"
}

function Init-SEC8 {
    Write-Host "COMING SOON!"
}

function Init-SEC9 {
    Write-Host "COMING SOON!"
}

function Init-SEC10 {
    Write-Host "COMING SOON!"
}

function Init-SEC11 {
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

    function Get-Ciphers {
        $ciphersPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"

        try {
            $des5656Check = (Get-ItemProperty -Path "$ciphersPath\DES 56/56" -ErrorAction Stop).Enabled
            $rc240128Check = (Get-ItemProperty -Path "$ciphersPath\RC2 40/128" -ErrorAction Stop).Enabled
            $rc256128Check = (Get-ItemProperty -Path "$ciphersPath\RC2 56/128" -ErrorAction Stop).Enabled
            $rc2128128Check = (Get-ItemProperty -Path "$ciphersPath\RC2 128/128" -ErrorAction Stop).Enabled
            $rc440128Check = (Get-ItemProperty -Path "$ciphersPath\RC4 40/128" -ErrorAction Stop).Enabled
            $rc456128Check = (Get-ItemProperty -Path "$ciphersPath\RC4 56/128" -ErrorAction Stop).Enabled
            $rc464128Check = (Get-ItemProperty -Path "$ciphersPath\RC4 64/128" -ErrorAction Stop).Enabled
            $rc4128128Check = (Get-ItemProperty -Path "$ciphersPath\RC4 128/128" -ErrorAction Stop).Enabled
            $3des168Check = (Get-ItemProperty -Path "$ciphersPath\Triple DES 168" -ErrorAction Stop).Enabled
            $aes128Check = (Get-ItemProperty -Path "$ciphersPath\AES 128/128" -ErrorAction Stop).Enabled
            $aes256Check = (Get-ItemProperty -Path "$ciphersPath\AES 256/256" -ErrorAction Stop).Enabled

            Write-Host "================================"
            Write-Host "             Ciphers             "
            Write-Host "================================"
            Write-Host "   DES 56/56: $(If ($des5656Check -eq 4294967295 -or $des5656Check -eq 1) {'Enabled'})"
            Write-Host "   RC2 40/128: $(If ($rc240128Check -eq 4294967295 -or $rc240128Check -eq 1) {'Enabled'})"
            Write-Host "   RC2 56/128: $(If ($rc256128Check -eq 4294967295 -or $rc256128Check -eq 1) {'Enabled'})"
            Write-Host "   RC2 128/128: $(If ($rc2128128Check -eq 4294967295 -or $rc2128128Check -eq 1) {'Enabled'})"
            Write-Host "   RC4 40/128: $(If ($rc440128Check -eq 4294967295 -or $rc440128Check -eq 1) {'Enabled'})"
            Write-Host "   RC4 56/128: $(If ($rc456128Check -eq 4294967295 -or $rc456128Check -eq 1) {'Enabled'})"
            Write-Host "   RC4 64/128: $(If ($rc464128Check -eq 4294967295 -or $rc464128Check -eq 1) {'Enabled'})"
            Write-Host "   RC4 128/128: $(If ($rc4128128Check -eq 4294967295 -or $rc4128128Check -eq 1) {'Enabled'})"
            Write-Host "   3DES 168: $(If ($3des168Check -eq 4294967295 -or $3des168Check -eq 1) {'Enabled'})"
            Write-Host "   AES 128/128: $(If ($aes128Check -eq 4294967295 -or $aes128Check -eq 1) {'Enabled'})"
            Write-Host "   AES 256/256: $(If ($aes256Check -eq 4294967295 -or $aes256Check -eq 1) {'Enabled'})"
            Write-Host "________________________________"
        } catch {
            Write-Host "Error accessing registry path: $ciphersPath"
        }
    }


    ################## MAIN ####################

    # Check SMB versions (SMB2 by default - if SMB1, check for legacy reasons)
    Get-SMBVersions

    # Check TLS values (Hardened: TLS1.2 client/server ---- BestPractice: >= TLS1.0 client/server)
    Get-TLSValues

    # Check hashes (Hardened: SHA 256/384/512 ---- BestPractice: All)
    Get-Hashes 

    # Check Ciphers (Hardened: AES only ---- BestPractice: AES,3DES)
    Get-Ciphers

    Write-Host ""
    $null = Read-Host "Press Enter to exit the script"
    Write-Host ""

    Sleep 1
    Banner-SEC99
    Sleep 1
    Exit
}

function Init-SEC12 {
   # Define the log name and filter criteria
   $logName = 'Security'
   $eventID = 4624

   # Get the events from the Security log with specific criteria for RDP logon
   $events = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$eventID] and EventData[Data[@Name='LogonType'] and (Data='10' or Data='7')]]" -MaxEvents 100

   # Display relevant information from the events
   foreach ($event in $events) {
       $time = $event.TimeCreated
       $user = $event.Properties[5].Value
       $sourceIP = $event.Properties[18].Value

       Write-Output "Time: $time"
       Write-Output "User: $user"
       Write-Output "Source IP: $sourceIP"
       Write-Output "---------------------------"
   }
}

function Init-SEC13 {
   $username = Read-Host 'In order to check credentials, we need to ensure the account is not locked out or
   hasnt surpassed any bad password counter limits. Please enter the account for review'

   # Get the user object from Active Directory
   $user = Get-ADUser -Identity $username -Properties badPwdCount, lockoutTime

   # Check if the account is locked out
   if ($user.lockoutTime -ne 0) {
       Write-Host "The account $username is currently locked out. Unlock the account first!"
   } elseif ($user.badPwdCount -ge $maxBadLogins_SEC13) {
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
}

function Init-SEC14 {
    Write-Host "COMING SOON!"
}

function Init-SEC15 {
    Write-Host ""
    $objectType = Read-Host "What object type are we pulling information for? (user/computer)"
    Write-Host ""

    switch ($objectType)
    {
        ## USER OBJECTS
        user {
            ## Prompt and store inputs
            $userList = Read-Host "Enter in the username(s), separated by spaces, for review"
            $users = $userList -split " "

            ## Pull information for users
            foreach ($user in $users) {
                $userInformation = Get-ADUser -Identity $user -Properties Name, SamAccountName, UserPrincipalName, `
                Enabled, Description, Comment, Info, Company, Department, Title, Manager, employeeID, employeeType, `
                extensionAttribute1, extensionAttribute3, extensionAttribute4, DistinguishedName, lastLogon, `
                PasswordLastSet, PasswordNeverExpires

                # Format last logon date properly
                $lastlogU = [datetime]::FromFileTime($userInformation.lastLogon).ToString('dd/MM/yyyy [HH:mm]')

                # Print relevant user information
                Write-Host "______________________________________________"
                Write-Host ""
                Write-Host "Name: $($userInformation.Name)"
                Write-Host "SamAccountName: $($userInformation.SamAccountName)"
                Write-Host "UserPrincipalName: $($userInformation.UserPrincipalName)"
                Write-Host "Enabled: $($userInformation.Enabled)"
                Write-Host "Description: $($userInformation.Description)"
                Write-Host "SEC-Attributes(Comment): $($userInformation.Comment)"
                Write-Host "Information: $($userInformation.Info)"
                Write-Host "Company: $($userInformation.Company)"
                Write-Host "Department: $($userInformation.Department)"
                Write-Host "Title: $($userInformation.Title)"
                Write-Host "Manager: $($userInformation.Manager)"
                Write-Host "Employee-ID: $($userInformation.employeeID)"
                Write-Host "Employee-Type (system[0],payroll[1],vendor[2],contractor[3]): $($userInformation.employeeType)"
                Write-Host "extensionAttribute1: $($userInformation.extensionAttribute1)"
                Write-Host "extensionAttribute3: $($userInformation.extensionAttribute3)"
                Write-Host "extensionAttribute4: $($userInformation.extensionAttribute4)"
                Write-Host "Last Logon: $lastLogU"
                Write-Host "Password Last Set: $($userInformation.PasswordLastSet)"
                Write-Host "Password-Never-Expires: $($userInformation.PasswordNeverExpires)"
                Write-Host "OU Path: $($userInformation.DistinguishedName)"
                Write-Host ""
                Write-Host "______________________________________________"

                ## Prompt for edits
                $promptEdit = Read-Host "Do you want to make any changes on this user's attributes? (yes/no)"
                Write-Host ""

                switch ($promptEdit) {
                    yes {
                        $editChoices = Read-Host "Which attribute(s) would you like to change? 
                        `n If there are multiple attributes to be changed, enter them all, separated by spaces.
                        `n (All other attributes can only be changed manually!)
                        `n INPUT OPTIONS:
                        `n comment/info/company/department/title/employeeid/employeetype/ext1/ext3/ext4/description/neverexpire"

                        $editAttributes = $editChoices.ToLower() -split " "

                        foreach ($editAttribute in $editAttributes) {
                            switch ($editAttribute) {
                                "description" {
                                    $newDescription = Read-Host "Enter new description"
                                    Set-ADUser -Identity $user -Description $newDescription
                                    Write-Host "Successfully changed the attribute for 'description'!" -ForegroundColor Green
                                }
                                "comment" {
                                    $newComment = Read-Host "Enter new comment"
                                    Set-ADUser -Identity $user -Replace @{comment=$newComment}
                                    Write-Host "Successfully changed the attribute for 'comment'!" -ForegroundColor Green
                                }
                                "info" {
                                    $newInfo = Read-Host "Enter new info"
                                    Set-ADUser -Identity $user -Replace @{info=$newInfo}
                                    Write-Host "Successfully changed the attribute for 'info'!" -ForegroundColor Green
                                }
                                "company" {
                                    $newCompany = Read-Host "Enter new company"
                                    Set-ADUser -Identity $user -Replace @{company=$newCompany}
                                    Write-Host "Successfully changed the attribute for 'company'!" -ForegroundColor Green
                                }
                                "neverexpire" {
                                    $newpne = Read-Host "Password-Never-Expires edit ($)(True/False)"
                                    Set-ADUser -Identity $user -PasswordNeverExpires $newpne
                                    Write-Host "Successfully changed the attribute for 'PasswordNeverExpires!'" -ForegroundColor Green
                                }
                                "department" {
                                    $newDepartment = Read-Host "Enter new department"
                                    Set-ADUser -Identity $user -Replace @{department=$newDepartment}
                                    Write-Host "Successfully changed the attribute for 'department'!" -ForegroundColor Green
                                }
                                "title" {
                                    $newTitle = Read-Host "Enter new title"
                                    Set-ADUser -Identity $user -Replace @{title=$newTitle}
                                    Write-Host "Successfully changed the attribute for 'Job Title'!" -ForegroundColor Green
                                }
                                "employeeid" {
                                    $newEmployeeID = Read-Host "Enter new employee ID"
                                    Set-ADUser -Identity $user -Replace @{employeeID=$newEmployeeID}
                                    Write-Host "Successfully changed the attribute for 'employeeID'!" -ForegroundColor Green
                                }
                                "employeetype" {
                                    $newEmployeeType = Read-Host "Enter new employee type (system[0],payroll[1],vendor[2],contractor[3])"
                                    Set-ADUser -Identity $user -Replace @{employeeType=$newEmployeeType}
                                    Write-Host "Successfully changed the attribute for 'employeeType'!" -ForegroundColor Green
                                }
                                "ext1" {
                                    $newExtAttr1 = Read-Host "Enter new value for extensionAttribute1"
                                    Set-ADUser -Identity $user -Replace @{extensionAttribute1=$newExtAttr1}
                                    Write-Host "Successfully changed the attribute for 'extensionAttribute1'!" -ForegroundColor Green
                                }
                                "ext3" {
                                    $newExtAttr3 = Read-Host "Enter new value for extensionAttribute3"
                                    Set-ADUser -Identity $user -Replace @{extensionAttribute3=$newExtAttr3}
                                    Write-Host "Successfully changed the attribute for 'extensionAttribute3'!" -ForegroundColor Green
                                }
                                "ext4" {
                                    $newExtAttr4 = Read-Host "Enter new value for extensionAttribute4"
                                    Set-ADUser -Identity $user -Replace @{extensionAttribute4=$newExtAttr4}
                                    Write-Host "Successfully changed the attribute for 'extensionAttribute4'!" -ForegroundColor Green
                                }
                                default {
                                    Write-Host "Invalid attribute - ensure attribute stated is from the provided list." -ForegroundColor Red
                                }
                            }
                        }
                    }
                        no {
                            Write-Host "No changes were made for user: $user" -ForegroundColor Yellow
                        }
                    }
                }
            }

        ## COMPUTER OBJECTS
        computer {
            ## Prompt and store inputs
            $compList = Read-Host "Enter in the computer(s), separated by spaces, for review"
            $computers = $compList -split " "

            ## Pull information for computers
            foreach ($computer in $computers) {
                $compInformation = Get-ADComputer -Identity $computer -Properties Name, DNSHostName, `
                Enabled, ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime, lastLogon, operatingSystem, PasswordLastSet, `
                DistinguishedName, servicePrincipalName, Description, Comment, Info

                # Format last logon time
                $lastlogC = [datetime]::FromFileTime($compInformation.lastLogon).ToString('dd/MM/yyyy [HH:mm]')

                # Format LAPS expiration
                $LAPSExpiration = [datetime]::FromFileTime($compInformation.'ms-Mcs-AdmPwdExpirationTime')

                # Print relevant computer information
                Write-Host "______________________________________________"
                Write-Host ""
                Write-Host "Computer Name: $($compInformation.Name)"
                Write-Host "HostName: $($compInformation.DNSHostName)"
                Write-Host "Enabled status: $($compInformation.Enabled)"
                Write-Host "LAPS Code: $($compInformation.'ms-Mcs-AdmPwd')"
                Write-Host "LAPS Expiration: $LAPSExpiration"
                Write-Host "Last Logon: $lastLogC"
                Write-Host "Operating System: $($compInformation.operatingSystem)"
                Write-Host "Password Last Set: $($compInformation.PasswordLastSet)"
                Write-Host "OU Path: $($compInformation.DistinguishedName)"
                Write-Host "SPN: $($compInformation.servicePrincipalName)"
                Write-Host "Description: $($compInformation.Description)"
                Write-Host "SecurityAttribute (comment): $($compInformation.Comment)"
                Write-Host "Information: $($compInformation.Info)"
                Write-Host ""
                Write-Host "______________________________________________"

                ## Prompt for edits
                $promptEdit = Read-Host "Do you want to make any changes on this computer's attributes? (yes/no)"
                Write-Host ""

                switch ($promptEdit) {
                    yes {
                        $editChoices = Read-Host "Which attribute(s) would you like to change? 
                        `n If there are multiple attributes to be changed, enter them all, separated by spaces.
                        `n (All other attributes can only be changed manually!)
                        `n INPUT OPTIONS:
                        `n comment/info/description"

                        $editAttributes = $editChoices.ToLower() -split " "

                        foreach ($editAttribute in $editAttributes) {
                            switch ($editAttribute) {
                                "comment" {
                                    $newComment = Read-Host "Enter new comment"
                                    Set-ADComputer -Identity $computer -Replace @{comment=$newComment}
                                    Write-Host "Successfully changed the attribute for 'comment'!" -ForegroundColor Green
                                }
                                "info" {
                                    $newInfo = Read-Host "Enter new info"
                                    Set-ADComputer -Identity $computer -Replace @{info=$newInfo}
                                    Write-Host "Successfully changed the attribute for 'info'!" -ForegroundColor Green
                                }
                                "description" {
                                    $newDescription = Read-Host "Enter new description"
                                    Set-ADComputer -Identity $computer -Description $newDescription
                                    Write-Host "Successfully changed the attribute for 'description'!" -ForegroundColor Green
                                }
                                default {
                                    Write-Host "Invalid attribute - ensure attribute stated is from the provided list." -ForegroundColor Red
                                }
                            }
                        }
                    }
                        no {
                            Write-Host "No changes were made for computer: $computer" -ForegroundColor Yellow
                        }
                    }
                }
            }
    }
     Sleep 1
     Banner-SEC99
     Sleep 1
     Exit
}

function Init-SEC16 {
   # Define the username for which you want to identify the lockout source
   $lockedOutUser = Read-Host "Enter username to check"

   # Search the Security event log for lockout events related to the specified user
   $events = Get-WinEvent -FilterHashtable @{
       LogName = 'Security'
       ID = 4740  # Event ID for account lockouts
   } -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*$lockedOutUser*" }

   if ($events) {
       Write-Host "Lockout events for user '$lockedOutUser':"
       $events | ForEach-Object {
           $time = $_.TimeCreated
           $message = $_.Message
           Write-Host "Event Time: $time"
           Write-Host "Message: $message"
           Write-Host "------------------------------------------"
       }
   } else {
       Write-Host "No lockout events found for user '$lockedOutUser'."
   }
}

function Init-SEC17 {
   Write-Host ""
   Write-Host "Checking enabled and disabled events in the last 24 hours....."
   Write-Host ""

   # Define the log name and event IDs for enabled and disabled events
   $logName = 'Security'
   $enabledEventID = 4722
   $disabledEventID = 4725

   # Query the event log for enabled events in the past 24 hours
   $enabledEvents = Get-WinEvent -LogName $logName -FilterXPath "*[System[(EventID=$enabledEventID) and TimeCreated[timediff(@SystemTime) <= 86400000]]]" -ErrorAction SilentlyContinue

   # Query the event log for disabled events in the past 24 hours
   $disabledEvents = Get-WinEvent -LogName $logName -FilterXPath "*[System[(EventID=$disabledEventID) and TimeCreated[timediff(@SystemTime) <= 86400000]]]" -ErrorAction SilentlyContinue

   Write-Host "=============ENABLED events=================" -ForegroundColor Green
   # Process the enabled events
   foreach ($event in $enabledEvents) {
       $eventDetails = $event.Message | Out-String
       $timestamp = $event.TimeCreated
       # Extract relevant information from $eventDetails and display or log it
       Write-Host "Enabled Event Timestamp: $timestamp"
       $eventDetails
   }

   Write-Host ""
   Write-Host ""
   Write-Host "===================================================================" -ForegroundColor Yellow
   Write-Host ""
   Write-Host ""
   Write-Host "============= DISABLED events =================" -ForegroundColor Red
   # Process the disabled events
   foreach ($event in $disabledEvents) {
       $eventDetails = $event.Message | Out-String
       $timestamp = $event.TimeCreated
       # Extract relevant information from $eventDetails and display or log it
       Write-Host "Disabled Event Timestamp: $timestamp"
       $eventDetails
   }
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

###################################################################################
################################### MAIN SCRIPT ###################################
###################################################################################

# Prompt the menu
while ($true) {
    Sleep 1
    $selection = Get-Choice
    Sleep 1
    Run-Banner($selection)
    Sleep 1
    Show-Prerequisites($selection)

    $capture0 = Read-Host "Do you wish to proceed with running [SEC$selection]? (y/n)"
    if ($capture0 -eq 'y') {
        # Initiate SEC0 protocol...
        Run-SecurityCode($selection)
    } elseif ($capture0 -eq 'n') {
        Write-Host ""
        Write-Host "No Security Code was run. Exiting script..." -ForegroundColor Red
        Write-Host ""
        Sleep 1
        Banner-SEC99
        Exit
    } else {
        Write-Host ""
        Write-Host "Not a valid choice! Exiting script..." -ForegroundColor Red
        Write-Host ""
        Sleep 1
        Banner-SEC99
        Exit
    }   
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
