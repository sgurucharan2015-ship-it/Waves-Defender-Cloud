#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$release = Join-Path $root 'client\build\Release'
$program = 'C:\Program Files\AegisAV'
$data = 'C:\ProgramData\AegisAV'

if (!(Test-Path (Join-Path $release 'AegisAV.exe'))) {
    throw 'AegisAV.exe is not built yet. Run client\build.bat first.'
}
New-Item -ItemType Directory -Force -Path $program,$data,(Join-Path $data 'Quarantine') | Out-Null
Copy-Item (Join-Path $release 'AegisAV.exe') $program -Force
Copy-Item (Join-Path $release 'AegisAV_UI.exe') $program -Force

$ini = Get-Content (Join-Path $root 'client\aegis.ini') -Raw
$ini = $ini.Replace('YOUR_WINDOWS_NAME', $env:USERNAME)
Set-Content -Path (Join-Path $data 'aegis.ini') -Value $ini -Encoding UTF8
Copy-Item (Join-Path $root 'client\seed_signatures.txt') (Join-Path $data 'signatures.txt') -Force

& (Join-Path $program 'AegisAV.exe') service-install
Write-Host ''
Write-Host 'Installed AegisAV.' -ForegroundColor Green
Write-Host 'IMPORTANT: Edit C:\ProgramData\AegisAV\aegis.ini and set ApiToken to the same token used by the server.'
Write-Host 'Then start the service:  sc.exe start AegisAVService'
