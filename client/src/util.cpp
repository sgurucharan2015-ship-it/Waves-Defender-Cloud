#include "aegis/core.h"
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <shlobj.h>

namespace aegis {

std::string to_utf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8,0,s.c_str(),(int)s.size(),nullptr,0,nullptr,nullptr);
    std::string out(n,'\0');
    WideCharToMultiByte(CP_UTF8,0,s.c_str(),(int)s.size(),out.data(),n,nullptr,nullptr);
    return out;
}
std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),nullptr,0);
    std::wstring out(n,L'\0');
    MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),out.data(),n);
    return out;
}
std::string verdict_string(Verdict v) {
    switch(v){case Verdict::Clean:return "clean";case Verdict::Suspicious:return "suspicious";case Verdict::Malicious:return "malicious";default:return "error";}
}

static fs::path program_data() {
    PWSTR p=nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData,0,nullptr,&p))) {
        fs::path r(p); CoTaskMemFree(p); return r;
    }
    return L"C:\\ProgramData";
}

static std::wstring read_ini(const fs::path& p, const wchar_t* section, const wchar_t* key, const wchar_t* def) {
    wchar_t buf[4096]{};
    GetPrivateProfileStringW(section,key,def,buf,4096,p.c_str());
    return buf;
}
static bool ini_bool(const fs::path& p,const wchar_t* sec,const wchar_t* key,bool def){
    auto v=read_ini(p,sec,key,def?L"1":L"0");
    return v==L"1"||v==L"true"||v==L"TRUE"||v==L"yes"||v==L"YES";
}

Config Config::load(const fs::path& supplied) {
    Config c;
    auto base = program_data()/L"AegisAV";
    std::error_code ec; fs::create_directories(base,ec);
    fs::path ini=supplied.empty()?base/L"aegis.ini":supplied;
    if(!fs::exists(ini)) {
        auto local=fs::current_path()/L"aegis.ini";
        if(fs::exists(local)) ini=local;
    }
    c.serverUrl=read_ini(ini,L"General",L"ServerUrl",c.serverUrl.c_str());
    c.apiToken=read_ini(ini,L"General",L"ApiToken",c.apiToken.c_str());
    c.onlineLookup=ini_bool(ini,L"General",L"OnlineLookup",true);
    c.uploadUnknown=ini_bool(ini,L"General",L"UploadUnknown",false);
    c.autoQuarantine=ini_bool(ini,L"General",L"AutoQuarantine",false);
    c.killMaliciousProcesses=ini_bool(ini,L"General",L"KillMaliciousProcesses",false);
    c.maxUploadBytes=std::stoull(read_ini(ini,L"General",L"MaxUploadMB",L"32"))*1024ull*1024ull;
    c.maxStaticReadBytes=std::stoull(read_ini(ini,L"General",L"MaxStaticReadMB",L"32"))*1024ull*1024ull;
    c.signaturesPath=read_ini(ini,L"Paths",L"Signatures",(base/L"signatures.txt").c_str());
    c.quarantinePath=read_ini(ini,L"Paths",L"Quarantine",(base/L"Quarantine").c_str());
    c.logPath=read_ini(ini,L"Paths",L"Log",(base/L"aegis.log").c_str());
    auto watches=read_ini(ini,L"Paths",L"Watch",L"");
    std::wstringstream ss(watches); std::wstring item;
    while(std::getline(ss,item,L';')) if(!item.empty()) c.watchPaths.emplace_back(item);
    fs::create_directories(c.signaturesPath.parent_path(),ec);
    fs::create_directories(c.quarantinePath,ec);
    return c;
}

void log_line(const Config& cfg, const std::string& line) {
    std::error_code ec; fs::create_directories(cfg.logPath.parent_path(),ec);
    std::ofstream f(cfg.logPath,std::ios::app);
    auto now=std::chrono::system_clock::now(); auto t=std::chrono::system_clock::to_time_t(now);
    std::tm tm{}; localtime_s(&tm,&t);
    f<<std::put_time(&tm,"%Y-%m-%d %H:%M:%S")<<" "<<line<<"\n";
}

}
