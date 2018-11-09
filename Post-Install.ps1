#Requires -RunAsAdministrator

$wc = New-Object System.Net.WebClient

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

# Ensure certificates/protocols work for https
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

# https://superuser.com/a/1067892
# disable wake for enabled scheduled tasks that are allowed to wake
$errorDisabling = $false
Get-ScheduledTask |
?{ $_.Settings.WakeToRun -eq $true -and $_.State -ne 'Disabled' } |
%{
    Try {
        write-host $_
        $_.Settings.WakeToRun = $false;
        Set-ScheduledTask $_
    } Catch {
        $errorDisabling = $true
    }
}

# Run Tasks Scheduler to disable remaining wake tasks if an error occurred
if ($errorDisabling) {
    write-host "There was an error disabling wake from sleep on some tasks. Running Task Scheduler with special permissions..."
    $pstoolsZipPath = "$PSScriptRoot/PSTools.zip"
    $pstoolsPath = "$PSScriptRoot/PSTools"
    $psexecPath = "$PSScriptRoot/PSTools/PsExec.exe"
    $wc.DownloadFile("https://download.sysinternals.com/files/PSTools.zip", $pstoolsZipPath)
    Expand-Archive -Path $pstoolsZipPath -DestinationPath $pstoolsPath -Force
    Start-Process -Filepath $psexecPath -ArgumentList @("-i", "-s control schedtasks") -Wait
    Remove-Item -Path $pstoolsZipPath
    Remove-Item -Path $pstoolsPath -Recurse
}

# disable wake for devices that are allowed to wake (list of wake capable devices: powercfg -devicequery wake_from_any)
powercfg -devicequery wake_armed |
%{
    if (($_ -notmatch '^(NONE)?$') -and ($_ -notmatch 'mouse') -and ($_ -notmatch 'keyboard')) {
        powercfg -devicedisablewake $_
        write-host "Disabled wake from sleep on: $_"
    }
}

# disable wake timers for all power schemes
powercfg -list | Select-String 'GUID' |
%{
    $guid = $_ -replace '^.*:\s+(\S+?)\s+.*$', '$1'
    powercfg -setdcvalueindex $guid SUB_SLEEP RTCWAKE 0
    powercfg -setacvalueindex $guid SUB_SLEEP RTCWAKE 0
}

# disable wake for automatic updates and for automatic maintenance
'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AUPowerManagement', 
'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance\WakeUp' |
%{
    $key = split-path $_
    $name = split-path $_ -leaf
    $type = 'DWORD'
    $value = 0
    if (!(Test-Path $key))
    { New-Item -Path $key -Force | Out-Null }
    if ((Get-ItemProperty $key $name 2>$null).$name -ne $value)
    { Set-ItemProperty $key $name $value -type $type }
}

# Setting power plan
$powerPlanName = "High Performance"
$confirmation = Read-Host "Would you like to set the power plan to '$powerPlanName'? (y/n)"
if ($confirmation -eq 'y') {
    $powerPlan = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerPlan -Filter "ElementName = '$powerPlanName'"
    if ($powerPlan -ne $null) {
        $powerPlanInstanceId = $powerPlan.InstanceID
        $powerPlanInstanceId -match ".*{([a-z0-9-]+)}"
        if ($Matches.Count -ge 2) {
            powercfg /setactive $Matches[1]
            Write-Host "Power plan set to '$powerPlanName'"
        } else {
            Write-Error "An error occurred when setting the power plan to '$powerPlanName'"
        }
    } else {
        Write-Error "Could not find power plan: '$powerPlanName'"
    }
}

# Disable UAC
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0

# Explorer launching to 'This PC'
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Value 1

# Disable show recently/frequently used files in Explorer Quick Access
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -Value 0
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -Value 0

# Enable automatic night light
$nightLightSetting = [byte[]](0x02,0x00,0x00,0x00,0x4f,0x58,0x1e,0x1d,0xc9,0x6f,0xd4,0x01,0x00,0x00,0x00,0x00,0x43,0x42,0x01,0x00,0x02,0x01,0xca,0x14,0x0e,0x15,0x00,0xca,0x1e,0x0e,0x07,0x00,0xcf,0x28,0xc8,0x2a,0xca,0x32,0x0e,0x12,0x2e,0x0f,0x00,0xca,0x3c,0x0e,0x07,0x2e,0x1f,0x00,0x00)
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\`$`$windows.data.bluelightreduction.settings\Current -Name Data -Value $nightLightSetting

# Disable OneDrive in Explorer
Set-ItemProperty -Path HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6} -Name System.IsPinnedToNameSpaceTree -Value 0

if (!(Get-Command choco -errorAction SilentlyContinue)) {
    Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
} else {
    choco upgrade chocolatey
}
choco install -y colemak googlechrome visualstudio2017community visualstudio2017-workload-nativedesktop geforce-experience steam logitechgaming

$apps = [ordered]@{
    "Battle.net"="https://us.battle.net/download/getInstaller?os=win&installer=Battle.net-Setup.exe";
    "PS4 Remote Play"="https://remoteplay.dl.playstation.net/remoteplay/module/win/RemotePlayInstaller.exe"
}

Foreach ($h in $apps.GetEnumerator()) {
    $confirmation = Read-Host "Would you like to install $($h.Name)? (y/n)"
    if ($confirmation -ne 'y') {continue}
    Write-Host "Installing" $h.Name
    $outpath = "$PSScriptRoot/"+ $h.Name + ".exe"
    $wc.DownloadFile($h.Value, $outpath)
    Start-Process -Filepath $outpath -Wait
    Remove-Item -Path $outpath
}

$confirmation = Read-Host "Would you like to install Qt? (y/n)"
if ($confirmation -eq 'y') {
    $qtTags = Invoke-WebRequest -Uri "https://api.github.com/repos/qt/qt5/tags" -UseBasicParsing | ConvertFrom-Json
    $qtVersion = $null
    Foreach ($tag in $qtTags)
    {
        if ($tag.name -eq $null) {continue}
        if ($tag.name -match "-") {continue}
        if (!$tag.name.StartsWith("v")) {continue}
        $qtVersion = $tag.name
        break
    }
    if ($qtVersion -ne $null) {
        $majorVersion = $qtVersion -match "v\d+\.\d+"
        if ($Matches.Count -ge 1) {
            $majorVersion = $Matches[0].substring(1)
            $totalVersion = $qtVersion.substring(1)
            $qtUrl = "http://download.qt.io/official_releases/qt/" + $majorVersion + "/" + $totalVersion + "/qt-opensource-windows-x86-" + $totalVersion + ".exe"
            $qtFilePath = "$PSScriptRoot/qt-opensource-windows-x86-" + $totalVersion + ".exe"
            Write-Host "Downloading Qt from url:" $qtUrl
            Import-Module BitsTransfer
            Start-BitsTransfer -Source $qtUrl -Destination $qtFilePath
            Start-Process -Filepath $qtFilePath -Wait
        } else {
            Write-Error "Qt version not in valid format"
        }
    } else {
        Write-Error "No valid Qt version found"
    }
}
