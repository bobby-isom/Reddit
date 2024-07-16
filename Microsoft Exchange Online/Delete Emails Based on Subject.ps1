#Install Modules
Install-Module -Name ExchangeOnlineManagement -Scope AllUsers

#Connect to Exchange 365
Connect-IPPSSession -UserPrincipalName EmailAddress

#Search with Subject in MM/DD/YYYY format
$Search=New-ComplianceSearch -Name "2022.06.10 Remove Phishing Email - Memorandum of sale" -ExchangeLocation All -ContentMatchQuery '(Received:06/10/2022..06/10/2022) AND (Subject:"Memorandum of sale  06/10/2022 06:57:37 am")'

#Enter the same name as the previous step
$SearchInfo = Read-Host "Enter Search Name"

#Starts the Compliance Search
Start-ComplianceSearch -Identity $Search.Identity

#Deletes the email from mailboxes
New-ComplianceSearchAction -SearchName $SearchInfo -Purge -PurgeType HardDelete

#Disconnect from Exchange 365
Disconnect-ExchangeOnline