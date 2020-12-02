# Allow script execution:
# PS> Set-ExecutionPolicy RemoteSigned -Force

# Check for administrative privileges
If (-Not ([Security.Principal.WindowsPrincipal]`
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")`
) {
    Write-Warning "This script must be run as an administrator."
    Return
}

# Suppress further warnings and errors
$WarningPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

echo "Creating system restore point..."
Enable-ComputerRestore $env:SystemDrive
Checkpoint-Computer "Pre-cleanup"

echo "Removing optional features..."
@(
    "Internet-Explorer-Optional-amd64"
    "MediaPlayback"
    "WindowsMediaPlayer"
    "MSRDC-Infrastructure"
    "Printing-PrintToPDFServices-Features"
    "Printing-XPSServices-Features"
    "Printing-Foundation-Features"
    "Printing-Foundation-InternetPrinting-Client"
    "SMB1Protocol"
    "WorkFolders-Client"
) |
% { Disable-WindowsOptionalFeature -FeatureName $_ -Online -NoRestart -Remove | Out-Null }

$capabilities = @(Get-WindowsCapability -Online | ? State -EQ "Installed")
@(
    "App.StepsRecorder*"
    "App.Support.QuickAssist*"
    "Browser.InternetExplorer*"
    "Hello.Face*"
    "Language.Handwriting*"
    "Language.OCR*"
    "Language.Speech*"
    "MathRecognizer*"
    "Media.WindowsMediaPlayer*"
    "Microsoft.Windows.MSPaint*"
    "Microsoft.Windows.WordPad*"
    "OneCoreUAP.OneSync*"
    "OpenSSH.Client*"
    "Print.Fax.Scan*"
    "Print.Management.Console*"
) |
% { $capabilities | ? Name -Like $_ | Remove-WindowsCapability -Online | Out-Null }

$apps = @(
    "Microsoft.3DBuilder"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingWeather"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.HEIFImageExtension"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MicrosoftStickyNotes"
    "Microsoft.MixedReality.Portal"
    "Microsoft.MSPaint"
    "Microsoft.Office.OneNote"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.ScreenSketch"
    "Microsoft.SkypeApp"
    "Microsoft.StorePurchaseApp"
    "Microsoft.VP9VideoExtensions"
    "Microsoft.Wallet"
    "Microsoft.WebpImageExtension"
    "Microsoft.WebMediaExtensions"
    "Microsoft.Windows.Photos"
    "Microsoft.WindowsAlarms"
    "Microsoft.WindowsCalculator"
    "Microsoft.WindowsCamera"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "microsoft.windowscommunicationsapps"
)

echo "Removing bundled apps..."
$apps | % { Get-AppxPackage -AllUsers | ? Name -EQ $_ | Remove-AppxPackage | Out-Null }

echo "And making sure they stay removed..."
$apps | % { Get-AppxProvisionedPackage -Online | ? DisplayName -EQ $_ | Remove-AppxProvisionedPackage -Online | Out-Null }

echo "Removing OneDrive..."
If ([System.Environment]::Is64BitOperatingSystem) { $appPath = "SysWOW64" } Else { $appPath = "System32" }
$oneDriveSetup = [IO.Path]::Combine($env:SystemRoot, "SysWOW64", "OneDriveSetup.exe")
If (Test-Path -Path $oneDriveSetup) { Start-Process $oneDriveSetup -ArgumentList "/uninstall" -Wait | Out-Null }

echo "Removing shortcut clutter from Explorer..."
@(
    "{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" # 3D Objects
    "{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" # Music
    "{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" # Pictures
    "{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" # Videos
    "{d3162b92-9365-467a-956b-92703aca08af}" # Documents
    "{088e3905-0323-4b02-9826-5d99428e115f}" # Downloads
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" # Desktop
) | % {
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\$_" /f | Out-Null
    reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\$_" /f | Out-Null
}

echo "Disabling sticky keys shortcut..."
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f | Out-Null

echo "Disabling filter keys shortcut..."
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f | Out-Null

echo "Disabling aero shake..."
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" /v "DisallowShaking" /t REG_DWORD /d "1" /f | Out-Null

echo "We need to reboot in order to complete the cleanup..."
pause
Restart-Computer -Force