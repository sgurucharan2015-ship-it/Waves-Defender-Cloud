#include "aegis/core.h"
#include <fstream>
#include <sstream>
#include <cmath>
#include <algorithm>
#include <cctype>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib,"wintrust.lib")
#pragma comment(lib,"crypt32.lib")

namespace aegis {

static std::string lower_ascii(std::string s){std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return (char)std::tolower(c);});return s;}
static bool contains_ci(const std::string& hay,const std::string& needle){return lower_ascii(hay).find(lower_ascii(needle))!=std::string::npos;}
static bool json_has(const std::string& body,const std::string& key,const std::string& value){
    return body.find("\""+key+"\":\""+value+"\"")!=std::string::npos || body.find("\""+key+"\": \""+value+"\"")!=std::string::npos;
}
static std::string json_string(const std::string& body,const std::string& key){
    auto k=body.find("\""+key+"\""); if(k==std::string::npos)return{}; auto c=body.find(':',k); if(c==std::string::npos)return{}; auto q=body.find('"',c+1); if(q==std::string::npos)return{}; auto e=body.find('"',q+1); if(e==std::string::npos)return{}; return body.substr(q+1,e-q-1);
}

Scanner::Scanner(Config cfg,SignatureDb* db):cfg_(std::move(cfg)),db_(db){}

double Scanner::entropy(const std::vector<unsigned char>& d){
    if(d.empty())return 0; double counts[256]{}; for(auto b:d)counts[b]++; double h=0; for(double n:counts)if(n){double p=n/d.size();h-=p*std::log2(p);}return h;
}

bool Scanner::is_authenticode_signed(const fs::path& path){
    WINTRUST_FILE_INFO fi{}; fi.cbStruct=sizeof(fi); fi.pcwszFilePath=path.c_str();
    GUID policy=WINTRUST_ACTION_GENERIC_VERIFY_V2; WINTRUST_DATA wd{}; wd.cbStruct=sizeof(wd); wd.dwUIChoice=WTD_UI_NONE; wd.fdwRevocationChecks=WTD_REVOKE_NONE; wd.dwUnionChoice=WTD_CHOICE_FILE; wd.pFile=&fi; wd.dwStateAction=WTD_STATEACTION_VERIFY; wd.dwProvFlags=WTD_CACHE_ONLY_URL_RETRIEVAL;
    LONG st=WinVerifyTrust(nullptr,&policy,&wd); wd.dwStateAction=WTD_STATEACTION_CLOSE; WinVerifyTrust(nullptr,&policy,&wd); return st==ERROR_SUCCESS;
}

void Scanner::static_heuristics(const fs::path& path,const std::vector<unsigned char>& data,ScanResult& r){
    std::string s((const char*)data.data(),data.size()); auto low=lower_ascii(s); auto ext=lower_ascii(to_utf8(path.extension().wstring()));
    auto add=[&](std::string n,int score,std::string detail){r.score+=score;r.findings.push_back({std::move(n),score,std::move(detail)});};
    bool script=ext==".ps1"||ext==".bat"||ext==".cmd"||ext==".vbs"||ext==".js"||ext==".jse"||ext==".wsf"||ext==".hta";
    bool pe=data.size()>2&&data[0]=='M'&&data[1]=='Z';
    if(script) add("Script file",5,"Executable script extension: "+ext);
    if(pe && !is_authenticode_signed(path)) add("Unsigned executable",10,"PE image has no valid cached Authenticode signature");
    if(data.size()>4096){double h=entropy(data); if(h>7.45)add("High entropy",15,"Entropy "+std::to_string(h)+" may indicate packing/encryption");}
    struct P{const char* text;int score;const char* name;};
    const P pats[]={
        {"downloadstring",25,"PowerShell downloader"},{"invoke-expression",20,"PowerShell dynamic execution"},{"iex(",18,"PowerShell IEX"},
        {"frombase64string",12,"Base64 decode"},{"-executionpolicy bypass",20,"Execution policy bypass"},{"-ep bypass",20,"Execution policy bypass"},
        {"-windowstyle hidden",12,"Hidden PowerShell"},{"-w hidden",12,"Hidden PowerShell"},{"new-object net.webclient",18,"WebClient downloader"},
        {"invoke-webrequest",12,"PowerShell web request"},{"start-bitstransfer",15,"BITS transfer"},{"certutil -urlcache",18,"Certutil downloader"},
        {"mshta ",18,"MSHTA execution"},{"rundll32 ",10,"Rundll32 execution"},{"regsvr32 ",10,"Regsvr32 execution"},
        {"virtualalloc",5,"Memory allocation API"},{"writeprocessmemory",12,"Process memory writing"},{"createremotethread",15,"Remote thread creation"},
        {"setwindowshookex",8,"Hook API"},{"urldownloadtofile",12,"URL download API"},{"winexec",6,"Process execution API"}
    };
    for(auto& p:pats) if(low.find(p.text)!=std::string::npos) add(p.name,p.score,p.text);
    auto name=lower_ascii(to_utf8(path.filename().wstring()));
    std::vector<std::string> doubleExt={".pdf.exe",".jpg.exe",".png.exe",".doc.exe",".docx.exe",".txt.exe",".zip.exe"};
    for(auto& x:doubleExt)if(name.size()>=x.size()&&name.ends_with(x)){add("Double extension",25,"Filename disguises an executable");break;}
    if((script||pe) && (low.find("http://")!=std::string::npos||low.find("https://")!=std::string::npos)) add("Embedded network URL",8,"Executable content contains an HTTP(S) URL");
    if(low.find("powershell")!=std::string::npos && low.find("hidden")!=std::string::npos && (low.find("download")!=std::string::npos||low.find("http")!=std::string::npos)) add("Hidden downloader combination",35,"PowerShell + hidden execution + network/download behavior");
    if(data.size()>=8 && data[0]==0xD0&&data[1]==0xCF&&data[2]==0x11&&data[3]==0xE0 && (low.find("vba")!=std::string::npos||low.find("macro")!=std::string::npos)) add("Office macro indicators",20,"OLE document contains VBA-related strings");
}

ScanResult Scanner::scan_file(const fs::path& path,bool allowOnline){
    ScanResult r; r.path=path; r.verdict=Verdict::Error;
    std::error_code ec; if(!fs::is_regular_file(path,ec)){r.error="Not a regular file";return r;}
    std::string err; r.sha256=sha256_file(path,err); if(r.sha256.empty()){r.error=err;return r;}
    std::string label; if(db_&&db_->contains(r.sha256,&label)){r.verdict=Verdict::Malicious;r.score=100;r.source="local-signature";r.findings.push_back({label,100,"SHA-256 match"});return r;}
    std::ifstream f(path,std::ios::binary); if(!f){r.error="Cannot read file";return r;}
    auto size=fs::file_size(path,ec); size_t take=(size_t)std::min<uintmax_t>(size,cfg_.maxStaticReadBytes); std::vector<unsigned char> data(take); f.read((char*)data.data(),(std::streamsize)take); data.resize((size_t)f.gcount());
    static_heuristics(path,data,r);
    if(allowOnline&&cfg_.onlineLookup&&!cfg_.serverUrl.empty()){
        auto url=cfg_.serverUrl+L"/v1/reputation/"+to_wide(r.sha256); auto hr=http_.get(url,cfg_.apiToken);
        if(hr.status==200){
            if(json_has(hr.body,"verdict","malicious")){r.score=std::max(r.score,100);r.source=json_string(hr.body,"source");r.findings.push_back({"Cloud reputation",100,"Known malicious by "+r.source});}
            else if(json_has(hr.body,"verdict","suspicious")){r.score=std::max(r.score,55);r.findings.push_back({"Cloud reputation",25,"Cloud service marked the hash suspicious"});}
        }
        if(r.score<50&&cfg_.uploadUnknown&&size<=cfg_.maxUploadBytes){
            std::vector<unsigned char> whole; whole.reserve((size_t)size); std::ifstream uf(path,std::ios::binary); whole.assign(std::istreambuf_iterator<char>(uf),{});
            auto ur=http_.post_binary(cfg_.serverUrl+L"/v1/scan/file",whole,cfg_.apiToken,path.filename().wstring());
            if(ur.status==200){if(json_has(ur.body,"verdict","malicious")){r.score=100;r.source="cloud-static";r.findings.push_back({"Cloud static scan",100,"Server-side scanning marked file malicious"});}else if(json_has(ur.body,"verdict","suspicious")){r.score=std::max(r.score,55);r.findings.push_back({"Cloud static scan",20,"Server-side static analysis is suspicious"});}}
        }
    }
    if(r.score>=80)r.verdict=Verdict::Malicious;else if(r.score>=35)r.verdict=Verdict::Suspicious;else r.verdict=Verdict::Clean;
    if(r.source.empty())r.source="local-analysis";
    return r;
}

void Scanner::scan_directory(const fs::path& root,const std::function<void(const ScanResult&)>& cb,std::atomic_bool* stop){
    std::error_code ec; fs::recursive_directory_iterator it(root,fs::directory_options::skip_permission_denied,ec),end;
    for(;it!=end;it.increment(ec)){if(stop&&stop->load())break;if(ec){ec.clear();continue;}if(it->is_regular_file(ec)){auto p=it->path();if(p.native().find(cfg_.quarantinePath.native())==0)continue;cb(scan_file(p));}}
}

bool Scanner::update_signatures(std::string& error){
    if(cfg_.serverUrl.empty()){error="ServerUrl is empty";return false;} auto hr=http_.get(cfg_.serverUrl+L"/v1/signatures?days=30",cfg_.apiToken); if(hr.status!=200){error=hr.error.empty()?"Signature server returned HTTP "+std::to_string(hr.status):hr.error;return false;}
    std::istringstream ss(hr.body);std::string line;size_t added=0;while(std::getline(ss,line)){if(line.empty()||line[0]=='#')continue;auto p=line.find(',');auto hash=line.substr(0,p);auto lab=p==std::string::npos?"Cloud.Known.Malware":line.substr(p+1);if(hash.size()==64){db_->merge(hash,lab);added++;}}
    if(!db_->save(cfg_.signaturesPath,error))return false; log_line(cfg_,"Updated signatures, merged "+std::to_string(added)+" entries");return true;
}

}
