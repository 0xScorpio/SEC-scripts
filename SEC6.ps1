Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [6]
  ____) |
 |_____/ 

____________________________________________________________________________________
[SEC6] Soft-delete user/computer object (recoverable for 60 days before full deletion)
____________________________________________________________________________________

"@ -ForegroundColor Cyan

#####################################################################################

# Variables
$OUPath = "OUPATH"
$inactiveDays = 100  # Change this to your desired threshold

# Prompt for 'user' or 'computer'
$objectType = Read-Host "Enter object type ('user' or 'computer')"

# Validate object type
if ($objectType -ne 'user' -and $objectType -ne 'computer') {
    Write-Host "Invalid object type. Exiting script."
    exit
}

# Get all objects based on the specified object type and OU path
if ($objectType -eq 'user') {
    $objects = Get-ADUser -Filter * -SearchBase $OUPath -Properties Description
} else {
    $objects = Get-ADComputer -Filter * -SearchBase $OUPath -Properties Description
}

# Loop through each object
foreach ($object in $objects) {
    $description = $object.Description

    # Check for the INACTIVE pattern and extract the number of days
    if ($description -match 'INACTIVE: (\d+) days') {
        $inactiveDaysForObject = [int]$Matches[1]

        # Check if the object should be deleted
        if ($inactiveDaysForObject -gt $inactiveDays) {
            # Get permanent deletion date based on tombstone lifetime
            $permanentDeletionDate = (Get-Date).AddDays((Get-ADObject -Identity $object.DistinguishedName -Properties TombstoneLifetime).TombstoneLifetime)

            # Delete the object
            Remove-ADObject -Identity $object.DistinguishedName -Confirm:$false

            # Print information about the deleted object
            Write-Host "Deleted $($objectType): $($object.Name)"
            Write-Host "Permanent deletion date: $($permanentDeletionDate.ToShortDateString())"
        } else {
            Write-Host "Skipping $($objectType): $($object.Name)"
        }
    } else {
        Write-Host "No INACTIVE information found for $($objectType): $($object.Name)"
    }
}
