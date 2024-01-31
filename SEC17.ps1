Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [17]
  ____) |
 |_____/ 

_____________________________________________________________________
[SEC17] Check all disabled/enabled object events in the past 24 hours
_____________________________________________________________________


"@ -ForegroundColor Cyan

# Set the time range for the past 24 hours
$startTime = (Get-Date).AddHours(-24)

# Define the log name and event IDs for enabled and disabled events
$logName = 'Security'
$enabledEventID = 4722
$disabledEventID = 4725

# Query the event log for enabled events in the past 12 hours
$enabledEvents = Get-WinEvent -LogName $logName -FilterXPath "*[System[(EventID=$enabledEventID) and TimeCreated[timediff(@SystemTime) <= 43200000]]]" -ErrorAction SilentlyContinue

# Query the event log for disabled events in the past 12 hours
$disabledEvents = Get-WinEvent -LogName $logName -FilterXPath "*[System[(EventID=$disabledEventID) and TimeCreated[timediff(@SystemTime) <= 43200000]]]" -ErrorAction SilentlyContinue

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
