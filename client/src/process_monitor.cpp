#include "aegis/core.h"
#include <tlhelp32.h>
#include <unordered_set>
#include <thread>
#include <chrono>

namespace aegis {
void ProcessMonitor::run(std::atomic_bool& stop,const std::function<void(const ScanResult&)>& cb){
    std::unordered_set<std::wstring> scanned;
    while(!stop){HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);if(snap!=INVALID_HANDLE_VALUE){PROCESSENTRY32W pe{};pe.dwSize=sizeof(pe);if(Process32FirstW(snap,&pe)){do{HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|(cfg_.killMaliciousProcesses?PROCESS_TERMINATE:0),FALSE,pe.th32ProcessID);if(p){wchar_t buf[32768];DWORD n=32768;if(QueryFullProcessImageNameW(p,0,buf,&n)){std::wstring path(buf,n);if(!scanned.contains(path)){scanned.insert(path);auto r=scanner_->scan_file(path);cb(r);if(r.verdict==Verdict::Malicious&&cfg_.killMaliciousProcesses){TerminateProcess(p,0xDEAD);log_line(cfg_,"Terminated malicious process: "+to_utf8(path));}}}CloseHandle(p);}}while(Process32NextW(snap,&pe));}CloseHandle(snap);}for(int i=0;i<10&&!stop;i++)std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}
}
