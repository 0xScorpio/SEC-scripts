Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [5]
  ____) |
 |_____/ 

_____________________________________________________
[SEC5] Just-In-Time Access for user/service accounts
_____________________________________________________

- [SEC5] will only enable/disable an account if it has been tagged.
- Logs all enable/disable timestamp history on the 'comment' attribute.
- Restricts from disabling an already disabled account & vice versa.

"@ -ForegroundColor Cyan

########################################################################
$sec5tag = "[SEC5] JIT Access"

# Prompt user for the service account
$serviceAccount = Read-Host "Enter the service account name"

# Check if the service account exists
$account = Get-ADUser -Identity $serviceAccount -Properties Enabled, Description, DistinguishedName, Comment -ErrorAction SilentlyContinue

if (-not $account) {
    Write-Host ""
    Write-Host "Service account '$serviceAccount' not found."
    Write-Host ""
    exit
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
    exit
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
        exit
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
        exit
    }
} elseif ($promptChoice -eq "exit") {
    exit
} else {
    Write-Host ""
    Write-Host "You entered $promptChoice which is not a valid input! Exiting..."
    Write-Host ""
    exit
}
