Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [16]
  ____) |
 |_____/ 

___________________________________________________________________
[SEC16] checks for locked out user events on the domain controller.
___________________________________________________________________

"@ -ForegroundColor Cyan

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
