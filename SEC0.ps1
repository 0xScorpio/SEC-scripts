Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [0]
  ____) |
 |_____/ 

____________________________________________________________________________________
[SEC0] filters Active Directory for SEC code descriptions - edit 'keywords' variable
____________________________________________________________________________________

"@ -ForegroundColor Cyan

# Specify the SEC keyword(s) to search for in the description
$keywords = "[SEC1]", "[SEC2]"

# Create an array to store individual filter conditions
$filterConditions = @()

# Build filter conditions for each keyword
foreach ($keyword in $keywords) {
    $filterConditions += "Description -like '*$keyword*'"
}

# Combine filter conditions using -or
$filterExpression = $filterConditions -join " -or "

# Search for objects based on the keywords in the description
$objects = Get-ADObject -Filter $filterExpression -Properties SamAccountName, Description

# Display the results
foreach ($object in $objects) {
    Write-Host "SAM Account Name: $($object.SamAccountName)"
    Write-Host "Description: $($object.Description)"
    Write-Host "--------------"
}
