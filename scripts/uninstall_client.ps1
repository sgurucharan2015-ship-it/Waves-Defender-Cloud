#Requires -RunAsAdministrator
$ErrorActionPreference = 'Continue'
$exe = 'C:\Program Files\AegisAV\AegisAV.exe'
if (Test-Path $exe) { & $exe service-uninstall }
Stop-Service AegisAVService -ErrorAction SilentlyContinue
Remove-Item 'C:\Program Files\AegisAV' -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Program files removed. C:\ProgramData\AegisAV was intentionally kept so quarantine and logs are not destroyed.'
