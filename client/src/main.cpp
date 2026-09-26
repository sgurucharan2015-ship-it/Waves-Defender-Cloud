#include "aegis/core.h"
#include <iostream>
#include <thread>
#include <csignal>
#include <cstdlib>

using namespace aegis;
static std::atomic_bool stopFlag{false};
static void on_sig(int){stopFlag=true;}

static void print_result(const ScanResult& r){
    std::cout<<"["<<verdict_string(r.verdict)<<"] "<<to_utf8(r.path.wstring());
    if(!r.sha256.empty())std::cout<<"\n  SHA256: "<<r.sha256;
    std::cout<<"\n  Score: "<<r.score<<"  Source: "<<r.source<<"\n";
    for(auto& f:r.findings)std::cout<<"   - +"<<f.score<<" "<<f.name<<": "<<f.detail<<"\n";
    if(!r.error.empty())std::cout<<"  Error: "<<r.error<<"\n";
}
static void maybe_quarantine(const Config& cfg,const ScanResult& r){if(r.verdict==Verdict::Malicious&&cfg.autoQuarantine){Quarantine q(cfg);std::string id,e;if(q.quarantine(r.path,r.sha256,id,e))std::cout<<"  QUARANTINED as "<<id<<"\n";else std::cout<<"  Quarantine failed: "<<e<<"\n";}}
static void usage(){
    std::cout<<"AegisAV 1.0\n\nCommands:\n"
             <<"  scan <file>                 Scan one file\n"
             <<"  scan-dir <folder>           Recursive folder scan\n"
             <<"  quick-scan                  Scan Downloads, Desktop and Temp\n"
             <<"  watch <folder>              Real-time folder protection\n"
             <<"  process-monitor             Scan newly observed running executables\n"
             <<"  update                      Download rolling 30-day signatures\n"
             <<"  quarantine <file>           Force quarantine a file\n"
             <<"  quarantine-list             List quarantined IDs\n"
             <<"  restore <id>                Restore quarantine item\n"
             <<"  service-install             Install Windows service (Admin)\n"
             <<"  service-uninstall           Remove Windows service (Admin)\n";
}
int wmain(int argc,wchar_t** argv){
    if(argc>=2&&std::wstring(argv[1])==L"service-run")return run_service();
    if(argc<2){usage();return 0;}
    Config cfg=Config::load();SignatureDb db;std::string err;if(!db.load(cfg.signaturesPath,err)){std::cerr<<err<<"\n";return 2;}Scanner scanner(cfg,&db);std::wstring cmd=argv[1];
    if(cmd==L"scan"&&argc>=3){auto r=scanner.scan_file(argv[2]);print_result(r);maybe_quarantine(cfg,r);return r.verdict==Verdict::Malicious?10:r.verdict==Verdict::Suspicious?5:0;}
    if(cmd==L"scan-dir"&&argc>=3){size_t n=0,bad=0;scanner.scan_directory(argv[2],[&](const ScanResult&r){n++;if(r.verdict!=Verdict::Clean){print_result(r);if(r.verdict==Verdict::Malicious)bad++;maybe_quarantine(cfg,r);}if(n%250==0)std::cout<<"Scanned "<<n<<" files...\n";},&stopFlag);std::cout<<"Done. Scanned "<<n<<", malicious "<<bad<<"\n";return bad?10:0;}
    if(cmd==L"quick-scan"){
        wchar_t* up=nullptr;size_t len=0;_wdupenv_s(&up,&len,L"USERPROFILE");std::vector<fs::path> roots;if(up){roots.push_back(fs::path(up)/L"Downloads");roots.push_back(fs::path(up)/L"Desktop");free(up);}wchar_t* tmp=nullptr;_wdupenv_s(&tmp,&len,L"TEMP");if(tmp){roots.emplace_back(tmp);free(tmp);}size_t n=0,bad=0;for(auto&r:roots)if(fs::exists(r))scanner.scan_directory(r,[&](const ScanResult&x){n++;if(x.verdict!=Verdict::Clean){print_result(x);if(x.verdict==Verdict::Malicious)bad++;maybe_quarantine(cfg,x);}},&stopFlag);std::cout<<"Quick scan complete: "<<n<<" files, "<<bad<<" malicious\n";return bad?10:0;}
    if(cmd==L"watch"&&argc>=3){signal(SIGINT,on_sig);std::cout<<"Watching "<<to_utf8(fs::path(argv[2]).wstring())<<". Ctrl+C to stop.\n";DirectoryWatcher w(&scanner,cfg);w.watch(argv[2],stopFlag,[&](const ScanResult&r){if(r.verdict!=Verdict::Clean){print_result(r);maybe_quarantine(cfg,r);}});return 0;}
    if(cmd==L"process-monitor"){signal(SIGINT,on_sig);ProcessMonitor pm(&scanner,cfg);pm.run(stopFlag,[&](const ScanResult&r){if(r.verdict!=Verdict::Clean){print_result(r);maybe_quarantine(cfg,r);}});return 0;}
    if(cmd==L"update"){if(scanner.update_signatures(err)){std::cout<<"Updated. Signatures loaded: "<<db.size()<<"\n";return 0;}std::cerr<<"Update failed: "<<err<<"\n";return 3;}
    if(cmd==L"quarantine"&&argc>=3){std::string e,h=sha256_file(argv[2],e);Quarantine q(cfg);std::string id;if(!h.empty()&&q.quarantine(argv[2],h,id,e)){std::cout<<"Quarantined as "<<id<<"\n";return 0;}std::cerr<<e<<"\n";return 4;}
    if(cmd==L"quarantine-list"){Quarantine q(cfg);for(auto&id:q.list())std::cout<<id<<"\n";return 0;}
    if(cmd==L"restore"&&argc>=3){Quarantine q(cfg);if(q.restore(to_utf8(argv[2]),err)){std::cout<<"Restored. Scan it before executing.\n";return 0;}std::cerr<<err<<"\n";return 4;}
    wchar_t exe[MAX_PATH];GetModuleFileNameW(nullptr,exe,MAX_PATH);
    if(cmd==L"service-install"){if(install_service(exe,err)){std::cout<<"Service installed. Start it with: sc start AegisAVService\n";return 0;}std::cerr<<err<<"\n";return 5;}
    if(cmd==L"service-uninstall"){if(uninstall_service(err)){std::cout<<"Service removed.\n";return 0;}std::cerr<<err<<"\n";return 5;}
    usage();return 1;
}
