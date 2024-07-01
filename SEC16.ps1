Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___   
  \___ \  ecurity Script [16]
   ____) |
  |_____/ 

___________________________________________________________________
[SEC16] checks for locked out user events on the domain controller.
___________________________________________________________________

"@ -ForegroundColor Cyan

# Define the username for which you want to identify the lockout source
$lockedOutUser = Read-Host "Enter username to check"

# Search the Security event log for lockout events related to the specified user
$events = Get-EventLog -LogName 'Security' -InstanceId 4740 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*$lockedOutUser*" }

if ($events) {
    Write-Host "Lockout events for user '$lockedOutUser':" -ForegroundColor Green
    $events | ForEach-Object {
        $time = $_.TimeGenerated
        $message = $_.Message
        Write-Host "Event Time: $time" -ForegroundColor Yellow
        Write-Host "Message: $message" -ForegroundColor Yellow
        Write-Host "------------------------------------------" -ForegroundColor Gray
    }
} else {
    Write-Host "No lockout events found for user '$lockedOutUser'." -ForegroundColor Red
}
