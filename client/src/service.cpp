#include "aegis/core.h"
#include <thread>
#include <vector>
#include <chrono>

namespace aegis {
static SERVICE_STATUS_HANDLE g_statusHandle=nullptr;
static SERVICE_STATUS g_status{};
static std::atomic_bool g_stop{false};
static HANDLE g_stopEvent=nullptr;

static void set_status(DWORD state,DWORD win32=NO_ERROR,DWORD hint=0){
    g_status.dwServiceType=SERVICE_WIN32_OWN_PROCESS;g_status.dwCurrentState=state;g_status.dwWin32ExitCode=win32;g_status.dwWaitHint=hint;
    g_status.dwControlsAccepted=(state==SERVICE_START_PENDING)?0:SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_statusHandle,&g_status);
}
static void WINAPI ctrl(DWORD code){if(code==SERVICE_CONTROL_STOP||code==SERVICE_CONTROL_SHUTDOWN){set_status(SERVICE_STOP_PENDING,NO_ERROR,3000);g_stop=true;if(g_stopEvent)SetEvent(g_stopEvent);}}
static void handle_result(const Config& cfg,const ScanResult& r){
    if(r.verdict==Verdict::Suspicious||r.verdict==Verdict::Malicious)log_line(cfg,"SERVICE "+verdict_string(r.verdict)+" "+to_utf8(r.path.wstring())+" sha256="+r.sha256+" score="+std::to_string(r.score));
    if(r.verdict==Verdict::Malicious&&cfg.autoQuarantine){Quarantine q(cfg);std::string id,err;if(q.quarantine(r.path,r.sha256,id,err))log_line(cfg,"Quarantined "+to_utf8(r.path.wstring())+" as "+id);else log_line(cfg,"Quarantine failed: "+err);}
}
static void WINAPI service_main(DWORD,LPWSTR*){
    g_statusHandle=RegisterServiceCtrlHandlerW(L"AegisAVService",ctrl);if(!g_statusHandle)return;set_status(SERVICE_START_PENDING,NO_ERROR,3000);g_stopEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    Config cfg=Config::load();SignatureDb db;std::string err;db.load(cfg.signaturesPath,err);Scanner scanner(cfg,&db);
    scanner.update_signatures(err); if(!err.empty())log_line(cfg,"Startup signature update: "+err);
    std::vector<std::thread> threads;
    for(auto& p:cfg.watchPaths){if(fs::exists(p)){threads.emplace_back([&,p]{DirectoryWatcher w(&scanner,cfg);w.watch(p,g_stop,[&](const ScanResult&r){handle_result(cfg,r);});});}}
    threads.emplace_back([&]{ProcessMonitor pm(&scanner,cfg);pm.run(g_stop,[&](const ScanResult&r){handle_result(cfg,r);});});
    set_status(SERVICE_RUNNING);
    auto lastUpdate=std::chrono::steady_clock::now();
    while(!g_stop){WaitForSingleObject(g_stopEvent,1000);if(std::chrono::steady_clock::now()-lastUpdate>std::chrono::hours(6)){std::string e;if(!scanner.update_signatures(e))log_line(cfg,"Signature update failed: "+e);lastUpdate=std::chrono::steady_clock::now();}}
    for(auto& t:threads)if(t.joinable())CancelSynchronousIo((HANDLE)t.native_handle());
    for(auto& t:threads)if(t.joinable())t.join();
    CloseHandle(g_stopEvent);g_stopEvent=nullptr;set_status(SERVICE_STOPPED);
}

bool install_service(const fs::path& exe,std::string& error){
    SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CREATE_SERVICE);if(!scm){error="OpenSCManager failed: "+std::to_string(GetLastError());return false;}
    std::wstring cmd=L"\""+exe.wstring()+L"\" service-run";
    SC_HANDLE s=CreateServiceW(scm,L"AegisAVService",L"AegisAV Real-time Protection",SERVICE_ALL_ACCESS,SERVICE_WIN32_OWN_PROCESS,SERVICE_AUTO_START,SERVICE_ERROR_NORMAL,cmd.c_str(),nullptr,nullptr,nullptr,nullptr,nullptr);
    if(!s){error="CreateService failed: "+std::to_string(GetLastError());CloseServiceHandle(scm);return false;}
    SERVICE_DESCRIPTIONW d{(LPWSTR)L"AegisAV user-mode real-time scanning and process reputation service."};ChangeServiceConfig2W(s,SERVICE_CONFIG_DESCRIPTION,&d);
    CloseServiceHandle(s);CloseServiceHandle(scm);return true;
}
bool uninstall_service(std::string& error){
    SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!scm){error="OpenSCManager failed";return false;}SC_HANDLE s=OpenServiceW(scm,L"AegisAVService",SERVICE_STOP|DELETE|SERVICE_QUERY_STATUS);if(!s){error="OpenService failed: "+std::to_string(GetLastError());CloseServiceHandle(scm);return false;}
    SERVICE_STATUS st{};ControlService(s,SERVICE_CONTROL_STOP,&st);if(!DeleteService(s)){error="DeleteService failed: "+std::to_string(GetLastError());CloseServiceHandle(s);CloseServiceHandle(scm);return false;}CloseServiceHandle(s);CloseServiceHandle(scm);return true;
}
int run_service(){SERVICE_TABLE_ENTRYW table[]={{(LPWSTR)L"AegisAVService",service_main},{nullptr,nullptr}};return StartServiceCtrlDispatcherW(table)?0:(int)GetLastError();}
}
