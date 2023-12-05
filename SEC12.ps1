Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [12]
  ____) |
 |_____/ 
"@ -ForegroundColor Cyan

Write-Host ""
Write-Host "___________________________________________________________________"
Write-Host "[SEC12] Reads RDP logon sessions that occurred recently on a server."
Write-Host "___________________________________________________________________"
Write-Host @"

"@ -ForegroundColor Cyan


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