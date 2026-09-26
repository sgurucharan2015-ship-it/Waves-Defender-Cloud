param([string]$AegisExe = 'C:\Program Files\AegisAV\AegisAV.exe')
# SAFE TEST: this script does NOT create malware. It only confirms the engine is callable.
if (!(Test-Path $AegisExe)) { throw "AegisAV not found: $AegisExe" }
& $AegisExe scan $PSCommandPath
