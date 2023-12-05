Write-Host ""
Write-Host @"
   _____  
  / ____| 
 | (___  
  \___ \ ecurity Script [14]
  ____) |
 |_____/ 
"@ -ForegroundColor Cyan

Write-Host ""
Write-Host "___________________________________________________________________________________________________________________________"
Write-Host "[SEC14] Checks enabled computers without LAPS and inactivity (60 days). Run script in phases (description, pings, disables)"
Write-Host "___________________________________________________________________________________________________________________________"
Write-Host @"

"@ -ForegroundColor Cyan


#List all Computer Objects without LAPS
Clear
## VARIABLE TO CHANGE ##
$OUpath = ""
$CharArray =$OUpath.Split(",")

$position = $CharArray[0].IndexOf("=")      
$CharArray[0].Substring($position+1)
$OUonly=$CharArray[0].Substring($position+1)

$OutFile ='c:\temp\' + $OUonly + '.csv'

#List all computer objects with flag Enabled=True + without ms-Mcs-AdmPwd (LAPS) + are inactive for 60 Days
$EnabledHosts=Get-ADComputer -Filter "Enabled -eq 'True' -and ms-Mcs-AdmPwd -notlike '*'" -SearchBase $OUpath `
-Properties ms-Mcs-AdmPwd,LastLogon | Select-object Name,ms-Mcs-AdmPwd,DNSHostName,DistinguishedName,Enabled,@{N='LastLogon'; E={[DateTime]::FromFileTime($_.LastLogon)}} `
 | Sort-Object LastLogon,DistinguishedName |  Where { $_.LastLogon -LT (Get-Date).AddDays(-60) }

$EnabledHosts | Export-Csv -Path $OutFile  -NoTypeInformation

#Count objects without LAPS activation
if ($EnabledHosts.count -eq 0)
{        [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
         [System.Windows.Forms.MessageBox]::Show('We have NO Computer Objects!!!','WARNING')} 
         else {[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
               [System.Windows.Forms.MessageBox]::Show('We have ' + $EnabledHosts.count+ ' Computer Objects!!!','WARNING')}

#Phase 2 - List inactive Computer Accounts 
$CountPings=0
foreach ($Hosts in $EnabledHosts)
{
    if ($EnabledHosts.count -le 50) #Prevent massive changes 
    {#Set-adcomputer -Identity $Hosts.Name -Enabled $false -Confirm
        $Hosts.NAME
        if ((Test-NetConnection -ComputerName $Hosts.NAME -Hops 1).PingSucceeded)
        {$CountPings+=1}
    }
}

if ($CountPings -gt 0)
        {[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
         [System.Windows.Forms.MessageBox]::Show('We have alive Computer Objects !!!','WARNING')}

#Phase 3 - Disable inactive Computer Accounts 
foreach ($Hosts in $EnabledHosts)
{
    if ($EnabledHosts.count -le 50) #Prevent massive changes
    {   $Hosts.NAME
        $Desc = '[SEC14] DISABLED due to no password change since 60 Days as of ' + "{0:dd/MM/yyyy}" -f (get-date)
        Set-adcomputer -Identity $Hosts.Name -Enabled $false  -Description $Desc -Confirm
    }
}