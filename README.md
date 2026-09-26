AegisAV
AegisAV is a Windows user-mode antivirus / endpoint protection project written in C++20, with a Python FastAPI reputation/signature server.
It is deliberately designed to be useful without doing dangerous things such as executing malware samples. Files are hashed and statically inspected; cloud lookups use hashes, and optional file upload sends raw bytes only to your own AegisAV server for static scanning.
What is included
Windows C++ endpoint
SHA-256 file hashing using Windows CNG / BCrypt.
Local rolling signature database.
Static heuristic analysis for scripts and PE files.
Detection of PowerShell download/execute patterns such as `DownloadString`, hidden PowerShell, execution-policy bypass, WebClient downloaders, Base64 decode chains, LOLBins and several injection-related API strings.
Authenticode verification for PE files.
Entropy analysis for packed/encrypted-looking files.
Double-extension detection (`invoice.pdf.exe`, etc.).
Recursive folder scanning.
Quick scan of Downloads, Desktop and TEMP.
Real-time directory monitoring with `ReadDirectoryChangesW`.
Running-process executable monitoring.
Optional process termination for confirmed malicious files (OFF by default).
Quarantine + restore.
Native Win32 GUI (`AegisAV_UI.exe`).
Windows Service support (`AegisAVService`).
Cloud hash reputation lookup.
Optional upload of unknown files to your own server (OFF by default for privacy).
Signature updates from your server.
Python reputation/signature server
FastAPI REST service.
SQLite threat database.
API-token authentication.
MalwareBazaar live SHA-256 lookups.
Automatic recent-MalwareBazaar ingestion.
Rolling 30-day signature export to endpoints.
Optional administrator-provided SHA-256 feed ingestion.
Optional URLhaus 30-day feed ingestion.
Server-side static file scanning.
Optional ClamAV scan when `clamscan` is installed on the server.
Unknown files are never executed.
Important reality check
This is a substantial antivirus codebase, but it is not a replacement for Microsoft Defender yet. Commercial Windows AV products also use Microsoft-signed kernel minifilter drivers, AMSI integration, ETW telemetry, exploit protection, behavior engines, sandbox farms, certificate reputation, cloud ML, anti-tamper components, enormous telemetry feeds, and dedicated security research teams.
Keep Microsoft Defender enabled while experimenting with AegisAV. Do not disable Defender to test this project.
1. Build the C++ endpoint
Requirements:
Windows 10/11 x64
Visual Studio 2022 with Desktop development with C++
CMake available in PATH
Open Developer PowerShell for VS 2022 and run:
```powershell
cd path\to\AegisAV\client
.\build.bat
```
Outputs:
```text
client\build\Release\AegisAV.exe
client\build\Release\AegisAV_UI.exe
```
No C++ package manager is needed. The endpoint uses Windows APIs only.
2. Configure the server
```powershell
cd path\to\AegisAV\server
Copy-Item .env.example .env
py generate_token.py
```
Copy the generated token into:
```text
server\.env                 -> AEGIS_TOKEN=
client\aegis.ini            -> ApiToken=
```
Obtain an abuse.ch Auth-Key and put it in:
```text
MALWAREBAZAAR_AUTH_KEY=
```
The server intentionally does not download malware samples from MalwareBazaar. It requests metadata/hash reputation only.
Optional feeds:
`URLHAUS_FEED_URL`: paste the authenticated 30-day JSON/CSV export URL provided in your URLhaus account.
`MALWARE_HASH_FEED_URL`: an administrator-controlled plaintext/CSV SHA-256 feed.
Start the server:
```powershell
.\run_server.bat
```
The default binds to `127.0.0.1:8787`, so it is reachable only from the same computer. For a remote server, put it behind HTTPS and a firewall rather than exposing the development Uvicorn listener directly.
3. Install the initial signatures/config
Run PowerShell as Administrator from the project root:
```powershell
.\scripts\install_client.ps1
```
This copies the executables to `C:\Program Files\AegisAV`, configuration/signatures to `C:\ProgramData\AegisAV`, substitutes your Windows username into the default watch paths, and installs the Windows service.
Edit:
```text
C:\ProgramData\AegisAV\aegis.ini
```
Set `ApiToken` to the same token as the server.
Then:
```powershell
sc.exe start AegisAVService
```
4. Commands
```powershell
AegisAV.exe scan "C:\path\file.exe"
AegisAV.exe scan-dir "C:\Users\You\Downloads"
AegisAV.exe quick-scan
AegisAV.exe watch "C:\Users\You\Downloads"
AegisAV.exe process-monitor
AegisAV.exe update
AegisAV.exe quarantine "C:\path\file.exe"
AegisAV.exe quarantine-list
AegisAV.exe restore <quarantine-id>
AegisAV.exe service-install
AegisAV.exe service-uninstall
```
`AegisAV_UI.exe` opens the native GUI.
Detection decision model
AegisAV intentionally separates confirmed malware from suspicious behavior:
SHA-256 local/cloud signature match -> malicious.
MalwareBazaar live match -> malicious.
ClamAV detection on the private server -> malicious.
Strong static heuristics alone -> suspicious unless the score is extremely high on the local endpoint.
No evidence -> clean locally or unknown in cloud reputation.
Heuristics are not perfect. Do not auto-delete suspicious files.
Privacy
`UploadUnknown=0` by default. In this mode, the endpoint sends only SHA-256 hashes to your server for reputation queries.
If you set `UploadUnknown=1`, unknown files up to `MaxUploadMB` are sent to your configured AegisAV server. Do not enable this for confidential files unless you control and trust that server.
Quarantine
Quarantine is non-destructive by design. AegisAV copies the file to:
```text
C:\ProgramData\AegisAV\Quarantine
```
then removes the original and writes metadata so it can be restored. `AutoQuarantine=0` by default.
The malicious PowerShell sample from this project
The seed signature database includes the SHA-256 of the PowerShell downloader examined while this project was created:
```text
61904b45e50738fe7780f40e960b230dfe464893e83e0ef624ef92d9481d8eeb
```
AegisAV will therefore detect that exact sample immediately, even with no server connection.
Recommended safe settings while developing
```ini
OnlineLookup=1
UploadUnknown=0
AutoQuarantine=0
KillMaliciousProcesses=0
```
Once you have tested your own benign files and confirmed the false-positive rate, you can enable quarantine. Keep process termination off until you are confident in the rules.
Server API
`GET /health`
`GET /v1/stats`
`GET /v1/reputation/{sha256}`
`GET /v1/signatures?days=30`
`POST /v1/scan/file`
`GET /v1/url/check?url=...`
`POST /v1/admin/update`
Except `/health`, endpoints require `X-Aegis-Token`.
Threat-intelligence notes
MalwareBazaar and URLhaus currently require abuse.ch Auth-Keys for API/feed use. Read their current fair-use and API terms before deploying AegisAV beyond personal/non-commercial use.
VirusTotal is intentionally not wired into the default server. Its public API terms place restrictions on using the public API as a substitute for antivirus products. If you have an appropriately licensed VirusTotal service, implement it as an additional provider rather than placing a public API key in the endpoint.
Next engineering steps for a commercial-grade version
Microsoft-signed filesystem minifilter for pre-execution interception.
AMSI provider/consumer integration for PowerShell, JavaScript and Office scripting telemetry.
ETW-based process/network/PowerShell event correlation.
YARA rule engine.
Archive/document parsers with strict decompression limits.
Secure signed update manifests and certificate pinning.
Local tamper protection and service ACL hardening.
Cloud sandbox with disposable VMs and no route to production networks.
Reputation for signer certificates, domains and URLs.
Differential signature updates rather than full rolling exports.
A test corpus with benign software, EICAR, and legally obtained malware research samples in isolated VMs.
Fuzzing of every file parser before enabling kernel-level interception.
