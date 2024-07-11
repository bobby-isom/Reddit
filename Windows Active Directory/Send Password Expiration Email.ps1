Start-Transcript -Path "C:\Scripts\Transcripts\AD\ADPassExp.log"
#################################################################################################################
#
# Password-Expiration-Notifications v20180412
# Highly Modified fork. https://gist.github.com/meoso/3488ef8e9c77d2beccfd921f991faa64
#
# Originally from v1.4 @ https://gallery.technet.microsoft.com/Password-Expiry-Email-177c3e27
# Robert Pearman (WSSMB MVP)
# TitleRequired.com
# Script to Automated Email Reminders when Users Passwords due to Expire.
#
# Requires: Windows PowerShell Module for Active Directory
#
##################################################################################################################
# Please Configure the following variables....
$SearchBase="DC=,DC="
$smtpServer=""
$expireindays = 7 #number of days of soon-to-expire paswords. i.e. notify for expiring in X days (and every day until $negativedays)
$negativedays = -3 #negative number of days (days already-expired). i.e. notify for expired X days ago
$from = ""
$logging = $true # Set to $false to Disable Logging
$logNonExpiring = $false
$logFile = "C:\Scripts\Logs\AD\PasswordExpiry\PasswordExpiry-" + (Get-Date).ToString('yyyy-MM-dd') + ".csv" # Exports the results to CSV by date so you have history over time
$testing = $false # Set to $false to Email Users
$adminEmailAddr = "" #multiple addr allowed but MUST be independent strings separated by comma
$sampleEmails = 3 #number of sample email to send to adminEmailAddr when testing ; in the form $sampleEmails="ALL" or $sampleEmails=[0..X] e.g. $sampleEmails=0 or $sampleEmails=3 or $sampleEmails="all" are all valid.
#
###################################################################################################################

# System Settings
$textEncoding = [System.Text.Encoding]::UTF8
$date = Get-Date -format yyyy-MM-dd

$starttime=Get-Date #need time also; don't use date from above

Write-Host "Processing `"$SearchBase`" for Password-Expiration-Notifications"

#set max sampleEmails to send to $adminEmailAddr
if ( $sampleEmails -isNot [int]) {
    if ( $sampleEmails.ToLower() -eq "all") {
    $sampleEmails=$users.Count
    } #else use the value given
}

if (($testing -eq $true) -and ($sampleEmails -ge 0)) {
    Write-Host "Testing only; $sampleEmails email samples will be sent to $adminEmailAddr"
} elseif (($testing -eq $true) -and ($sampleEmails -eq 0)) {
    Write-Host "Testing only; emails will NOT be sent"
}

# Create CSV Log
if ($logging -eq $true) {
    #Always purge old CSV file
    Out-File $logfile
    Add-Content $logfile "`"Date`",`"SAMAccountName`",`"DisplayName`",`"Created`",`"PasswordSet`",`"DaystoExpire`",`"ExpiresOn`",`"EmailAddress`",`"Notified`""
}

# Get Users From AD who are Enabled, Passwords Expire
Import-Module ActiveDirectory
$users = get-aduser -SearchBase $SearchBase -Filter {(enabled -eq $true) -and (passwordNeverExpires -eq $false)} -properties sAMAccountName, displayName, PasswordNeverExpires, PasswordExpired, PasswordLastSet, EmailAddress, lastLogon, whenCreated, Manager

$DefaultmaxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge

$countprocessed=${users}.Count
$samplesSent=0
$countsent=0
$countnotsent=0
$countfailed=0

# Process Each User for Password Expiry
foreach ($user in $users) { 
    $Manager = (Get-ADUser -Identity $User.sAMAccountName -Properties manager).manager

    #If the person's manager has no email address in AD, sent the email to a specific address.
    If ($Manager -eq $null) {
    $ManagerEmail = ""
    }
    else {
    $ManagerEmail = (Get-ADUser -Identity $Manager -Properties EMailAddress).EMailAddress
    }

    $dName = $user.displayName
    $sName = $user.sAMAccountName
    $emailaddress = $user.emailaddress
    $whencreated = $user.whencreated
    $passwordSetDate = $user.PasswordLastSet
    $sent = "" # Reset Sent Flag

    $PasswordPol = (Get-AduserResultantPasswordPolicy $user)
    # Check for Fine Grained Password
    if (($PasswordPol) -ne $null) {
        $maxPasswordAge = ($PasswordPol).MaxPasswordAge
    } else {
        # No FGPP set to Domain Default
        $maxPasswordAge = $DefaultmaxPasswordAge
    }

    #If maxPasswordAge=0 then same as passwordNeverExpires, but PasswordCannotExpire bit is not set
    if ($maxPasswordAge -eq 0) {
        Write-Host "$sName MaxPasswordAge = $maxPasswordAge (i.e. PasswordNeverExpires) but bit not set."
    }

    $expiresOn = $passwordsetdate + $maxPasswordAge
    $today = (get-date)

    if ( ($user.passwordexpired -eq $false) -and ($maxPasswordAge -ne 0) ) {   #not Expired and not PasswordNeverExpires
		$daystoexpire = (New-TimeSpan -Start $today -End $expiresOn).Days
    } elseif ( ($user.passwordexpired -eq $true) -and ($passwordSetDate -ne $null) -and ($maxPasswordAge -ne 0) ) {   #if expired and passwordSetDate exists and not PasswordNeverExpires
        # i.e. already expired
    	$daystoexpire = -((New-TimeSpan -Start $expiresOn -End $today).Days)
    } else {
        # i.e. (passwordSetDate = never) OR (maxPasswordAge = 0)
    	$daystoexpire="NA"
        #continue #"continue" would skip user, but bypass any non-expiry logging
    }

    Write-Output "Begin force change modification"
    Write-Output "Current User: $dName"
    Write-Output "Days to expire: $daystoexpire"
    Write-Output "Manager:" $manager
    Write-Output "Manager Email Address:" $managerEmail

    if ($daystoexpire -lt 1) {
        Write-Output "THIS USER WILL BE FORCE PASSWORD CHANGED"
        Set-ADUser -Identity $sName -ChangePasswordAtLogon $true
    }
    Write-Output "End force change modification"

    #Write-Host "$sName DtE: $daystoexpire MPA: $maxPasswordAge" #debug

    # Set verbiage based on Number of Days to Expiry.
    Switch ($daystoexpire) {
        {$_ -ge $negativedays -and $_ -le "-1"} {$messageDays = "has expired"}
        "0" {$messageDays = "will expire today"}
        "1" {$messageDays = "will expire in 1 day"}
        default {$messageDays = "will expire in " + "$daystoexpire" + " days"}
    }

    # Email Subject Set Here
    $subject="Urgent: Your password $messageDays"

    # Email Body Set Here, Note You can use HTML, including Images.
    $body="
    
    <p style=`"font-family:verdana;font-size:11;`"><b><i>This email was sent from an unmonitored mailbox, please do not reply.</i></b></p>

    <br>
    
    <p style=`"font-family:verdana;font-size:11;`">Hi $dName,</p>

    <p style=`"font-family:verdana;font-size:11;`"><b>Urgent:</b> Your Active Directory password for your <b>$sName</b> account $messageDays and requires your immediate attention.</p>
        
    <br>

    <p style=`"font-family:verdana;font-size:11;`">When your password has expired, you will be unable to login and connect to Sophos Connect and will be unable to reset your password.</p>

    <br>
      
    <p style=`"font-family:verdana;font-size:11;`"><b>Remote working?</b></p>

    <p style=`"font-family:verdana;font-size:11;`">We recommend changing your password now. To do this, do the following;</p>

    <p style=`"font-family:verdana;font-size:11;`">1. On a Windows machine, press Ctrl-Alt-Del and select `"Change Password`".</p>

    <p style=`"font-family:verdana;font-size:11;`">2. Open Sophos Connect and press disconnect.</p>

    <p style=`"font-family:verdana;font-size:11;`">3. Connect to the VPN connection and enter your username as <b>$sName</b> and new password.</p>

    <p style=`"font-family:verdana;font-size:11;`">When your password has expired, you will be unable to login and connect to the VPN and will be unable to reset your password.</p>

    <p style=`"font-family:verdana;font-size:11;`">If this happens, please call XXXX and request a password reset.</p

    <br>

    <p style=`"font-family:verdana;font-size:11;`"><b>In the office?</b></p>

    <p style=`"font-family:verdana;font-size:11;`">On a Windows machine, press Ctrl-Alt-Del and select `"Change Password`".</p>

    <p style=`"font-family:verdana;font-size:11;`">If you do not know your current password, call XXXX and request a password reset.</a></p>

    <br>

    <p style=`"font-family:verdana;font-size:11;`"><b>Still having issues?</b></p>

    <p style=`"font-family:verdana;font-size:11;`">Please open Teamviewer and then call XXXX.</p>

    <p style=`"font-family:verdana;font-size:11;`">Thank you</p>
    "

    # If testing-enabled and send-samples, then set recipient to adminEmailAddr else user's EmailAddress
    if (($testing -eq $true) -and ($samplesSent -lt $sampleEmails)) {
        $recipient = $adminEmailAddr
    } else {
        $recipient = $emailaddress
    }

    #if in trigger range, send email
    if ( ($daystoexpire -ge $negativedays) -and ($daystoexpire -lt $expireindays) -and ($daystoexpire -ne "NA") ) {
        # Send Email Message
        if (($emailaddress) -ne $null) {
            if ( ($testing -eq $false) -or (($testing -eq $true) -and ($samplesSent -lt $sampleEmails)) ) {
                try {
                    Send-Mailmessage -smtpServer $smtpServer -from $from -to $recipient -cc $managerEmail -subject $subject -body $body -bodyasHTML -priority High -Encoding $textEncoding -ErrorAction Stop -ErrorVariable err
                } catch {
                    write-host "Error: Could not send email to $recipient via $smtpServer"
                    write-host $_
                    $sent = "Send fail"
                    $countfailed++
                } finally {
                    if ($err.Count -eq 0) {
                        write-host "Sent email for $sName to $recipient"
                        $countsent++
                        if ($testing -eq $true) {
                            $samplesSent++
                            $sent = "toAdmin"
                        } else { $sent = "Yes" }
                    }
                }
            } else {
                Write-Host "Testing mode: skipping email to $recipient"
                $sent = "No"
                $countnotsent++
            }
        } else {
            Write-Host "$dName ($sName) has no email address."
            $sent = "No addr"
            $countnotsent++
        }

        # If Logging is Enabled Log Details
        if ($logging -eq $true) {
            Add-Content $logfile "`"$date`",`"$sName`",`"$dName`",`"$whencreated`",`"$passwordSetDate`",`"$daystoExpire`",`"$expireson`",`"$emailaddress`",`"$sent`""
        }
    } else {
        #if ( ($daystoexpire -eq "NA") -and ($maxPasswordAge -eq 0) ) { Write-Host "$sName PasswordNeverExpires" } elseif ($daystoexpire -eq "NA") { Write-Host "$sName PasswordNeverSet" } #debug
        # Log Non Expiring Password
        if ( ($logging -eq $true) -and ($logNonExpiring -eq $true) ) {
            if ($maxPasswordAge -eq 0 ) {
                $sent = "NeverExp"
            } else {
                $sent = "No"
            }
            Add-Content $logfile "`"$date`",`"$sName`",`"$dName`",`"$whencreated`",`"$passwordSetDate`",`"$daystoExpire`",`"$expireson`",`"$emailaddress`",`"$sent`""
        }
    }

} # End User Processing

$endtime=Get-Date
$totaltime=($endtime-$starttime).TotalSeconds
$minutes="{0:N0}" -f ($totaltime/60)
$seconds="{0:N0}" -f ($totaltime%60)

Write-Host "$countprocessed Users from `"$SearchBase`" Processed in $minutes minutes $seconds seconds."
Write-Host "Email trigger range from $negativedays (past) to $expireindays (upcoming) days of user's password expiry date."
Write-Host "$countsent Emails Sent."
Write-Host "$countnotsent Emails skipped."
Write-Host "$countfailed Emails failed."

if ($logging -eq $true) {
    #sort the CSV file
    Rename-Item $logfile "$logfile.old"
    import-csv "$logfile.old" | sort ExpiresOn | export-csv $logfile -NoTypeInformation
    Remove-Item "$logFile.old"
    Write-Host "CSV File created at ${logfile}."

    #email the CSV and stats to admin(s) 
    if ($testing -eq $true) {
        $body="<b><i>Testing Mode.</i></b><br>"
    } else {
        $body=""
    }

    $body+="
    CSV Attached for $date<br>
    $countprocessed Users from `"$SearchBase`" Processed in $minutes minutes $seconds seconds.<br>
    Email trigger range from $negativedays (past) to $expireindays (upcoming) days of user's password expiry date.<br>
    $countsent Emails Sent.<br>
    $countnotsent Emails skipped.<br>
    $countfailed Emails failed.
    "

    try {
        Send-Mailmessage -smtpServer $smtpServer -UseSsl -from $from -to $adminEmailAddr -subject "Password Expiry Logs" -body $body -bodyasHTML -Attachments "$logFile" -priority High -Encoding $textEncoding -ErrorAction Stop -ErrorVariable err
    } catch {
         write-host "Error: Failed to email CSV log to $adminEmailAddr via $smtpServer"
    } finally {
        if ($err.Count -eq 0) {
            write-host "CSV emailed to $adminEmailAddr"
        }
    }
}
# End
Stop-Transcript
