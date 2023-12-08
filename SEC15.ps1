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
                    `n comment/info/company/department/title/employeeid/employeetype/ext1/ext3/ext4/description"

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
