Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [15]
  ____) |
 |_____/ 

________________________________________________________________
[SEC15] Displays user/computer information and prompts for edits
________________________________________________________________
"@ -ForegroundColor Cyan


######################## DISPLAY USER/COMPUTER CONFIGURATION ##########################
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
            PasswordLastSet

            # Format last logon date properly
            $lastlogU = [datetime]::FromFileTime($user.lastLogon).ToString('dd/MM/yyyy [HH:mm]')

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
            Write-Host "OU Path: $($userInformation.DistinguishedName)"
            Write-Host ""

            ## Prompt for edits
            $promptEdit = Read-Host "Do you want to make any changes on this user's attributes? (yes/no)"
            Write-Host ""

            switch ($promptEdit) {
            yes {
                $editChoices = Read-Host "Which attribute(s) would you like to change? 
                `n If there are multiple attributes to be changed, enter them all, separated by spaces.
                `n (All other attributes can only be changed manually!)
                `n INPUT OPTIONS:
                `n comment/info/company/department/title/employeeid/employeetype/ext1/ext3/ext4"

                $editAttributes = $editChoices.ToLower() -split " "

                foreach ($editAttribute in $editAttributes) {
                    switch ($editAttribute) {
                        "comment" {
                            $newComment = Read-Host "Enter new comment"
                            Set-ADUser -Identity $user -Description $newComment
                        }
                        "info" {
                            $newInfo = Read-Host "Enter new info"
                            Set-ADUser -Identity $user -Replace @{info=$newInfo}
                        }
                        "company" {
                            $newCompany = Read-Host "Enter new company"
                            Set-ADUser -Identity $user -Replace @{company=$newCompany}
                        }
                        "department" {
                            $newDepartment = Read-Host "Enter new department"
                            Set-ADUser -Identity $user -Replace @{department=$newDepartment}
                        }
                        "title" {
                            $newTitle = Read-Host "Enter new title"
                            Set-ADUser -Identity $user -Replace @{title=$newTitle}
                        }
                        "employeeid" {
                            $newEmployeeID = Read-Host "Enter new employee ID"
                            Set-ADUser -Identity $user -Replace @{employeeID=$newEmployeeID}
                        }
                        "employeetype" {
                            $newEmployeeType = Read-Host "Enter new employee type (system[0],payroll[1],vendor[2],contractor[3])"
                            Set-ADUser -Identity $user -Replace @{employeeType=$newEmployeeType}
                        }
                        "ext1" {
                            $newExtAttr1 = Read-Host "Enter new value for extensionAttribute1"
                            Set-ADUser -Identity $user -Replace @{extensionAttribute1=$newExtAttr1}
                        }
                        "ext3" {
                            $newExtAttr3 = Read-Host "Enter new value for extensionAttribute3"
                            Set-ADUser -Identity $user -Replace @{extensionAttribute3=$newExtAttr3}
                        }
                        "ext4" {
                            $newExtAttr4 = Read-Host "Enter new value for extensionAttribute4"
                            Set-ADUser -Identity $user -Replace @{extensionAttribute4=$newExtAttr4}
                        }
                        default {
                            Write-Host "Invalid attribute - ensure attribute stated is from the provided list."
                        }
                    }
                }
            }
                no {
                    Write-Host "No changes were made for user: $user"
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
    }
}