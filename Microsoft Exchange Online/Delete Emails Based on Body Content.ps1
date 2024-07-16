#Install Modules
Install-Module -Name ExchangeOnlineManagement -Scope AllUsers

#Connect to Exchange 365
Connect-IPPSSession -UserPrincipalName EmailAddress

#Search with Body
$Search=New-ComplianceSearch -Name $SearchInfo -ExchangeLocation All -ContentMatchQuery '(Received:03/10/2020..03/10/2020) AND (Body:"Gavi Sandhu shared the folder "Lifetime Wealth Management Ltd" with you."'

#Enter the same name as the previous step
$SearchInfo = Read-Host "Enter Search Name"

#Starts the Compliance Search
Start-ComplianceSearch -Identity $Search.Identity

#Deletes the email from mailboxes
New-ComplianceSearchAction -SearchName $SearchInfo -Purge -PurgeType HardDelete

#Disconnect from Exchange 365
Disconnect-ExchangeOnline