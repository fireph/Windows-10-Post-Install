#Requires -RunAsAdministrator

$wc = New-Object System.Net.WebClient

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

Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Value 1

if (!(Get-Command choco -errorAction SilentlyContinue)) {
    Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
} else {
    choco upgrade chocolatey
}
choco install -y colemak googlechrome visualstudio2017community visualstudio2017-workload-nativedesktop geforce-experience steam

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
