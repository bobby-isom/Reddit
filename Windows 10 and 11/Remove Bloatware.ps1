$packages = @(
"7EE7776C.LinkedInforWindows"
"C27EB4BA.DropboxOEM"
"Microsoft.3DBuilder"
"Microsoft.Microsoft3DViewer"
"Microsoft.Advertising.Xaml"
"Microsoft.Appconnector"
"Microsoft.BingFinance"
"Microsoft.BingFoodAndDrink"
"Microsoft.BingHealthAndFitness"
"Microsoft.BingNews"
"Microsoft.BingSports"
"Microsoft.BingTravel"
"Microsoft.BingWeather"
"Microsoft.CommsPhone"
"Microsoft.ConnectivityStore"
"Microsoft.DesktopAppInstaller"
"Microsoft.Getstarted"
"Microsoft.Messaging"
"Microsoft.Microsoft3DViewer"
"Microsoft.MicrosoftOfficeHub"
"Microsoft.MicrosoftSolitaireCollection"
"Microsoft.MixedReality.Portal"
"Microsoft.Netflix"
"Microsoft.NetworkSpeedTest"
"Microsoft.Office.Desktop"
"Microsoft.Office.OneNote"
"Microsoft.Office.Sway"
"Microsoft.OfficeLens"
"Microsoft.OneConnect"
"Microsoft.OneDrive"
"Microsoft.People"
"Microsoft.Print3D"
"Microsoft.RemoteDesktop"
"Microsoft.SkypeApp"
"Microsoft.Wallet"
"Microsoft.Windows.CloudExperienceHost"
"Microsoft.Windows.NarratorQuickStart"
"Microsoft.Windows.PeopleExperienceHost"
"Microsoft.Windows.Photos"
"Microsoft.WindowsAlarms"
"Microsoft.WindowsCamera"
"Microsoft.windowscommunicationsapps"
"Microsoft.WindowsFeedbackHub"
"Microsoft.WindowsMaps"
"Microsoft.WindowsPhone"
"Microsoft.WindowsReadingList"
"Microsoft.WindowsSoundRecorder"
"Microsoft.Xbox.TCUI"
"Microsoft.XboxApp"
"Microsoft.XboxGameCallableUI"
"Microsoft.XboxGameOverlay"
"Microsoft.XboxGamingOverlay"
"Microsoft.XboxIdentityProvider"
"Microsoft.XboxLive"
"Microsoft.XboxSpeechToTextOverlay"
"Microsoft.YourPhone"
"Microsoft.ZuneMusic"
"Microsoft.ZuneVideo"
"Windows.CBSPreview"
)

ForEach ($packages in $packages) {
Get-AppxPackage -Name $packages | Remove-AppxPackage -erroraction 'silentlycontinue'

} 