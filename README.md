# Windows-10-Post-Install
Setup your Windows 10 machine after an install in a flash!

## How to run

Run this code in an admin Powershell window:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DungFu/Windows-10-Post-Install/master/Post-Install.ps1'))
```
