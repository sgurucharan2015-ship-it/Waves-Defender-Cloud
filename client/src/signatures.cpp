#include "aegis/core.h"
#include <fstream>
#include <algorithm>

namespace aegis {
bool SignatureDb::load(const fs::path& path, std::string& error){
    labels_.clear();
    if(!fs::exists(path)) return true;
    std::ifstream f(path); if(!f){error="Cannot open signature database";return false;}
    std::string line; while(std::getline(f,line)){
        if(line.empty()||line[0]=='#') continue;
        auto p=line.find(','); std::string h=line.substr(0,p); std::string label=p==std::string::npos?"Known.Malware":line.substr(p+1);
        std::transform(h.begin(),h.end(),h.begin(),::tolower);
        if(h.size()==64) labels_[h]=label;
    } return true;
}
bool SignatureDb::save(const fs::path& path, std::string& error) const{
    std::error_code ec; fs::create_directories(path.parent_path(),ec);
    auto tmp=path; tmp+=L".tmp"; std::ofstream f(tmp,std::ios::trunc); if(!f){error="Cannot write signature database";return false;}
    f<<"# sha256,label\n"; for(auto& [h,l]:labels_) f<<h<<","<<l<<"\n"; f.close();
    fs::rename(tmp,path,ec); if(ec){fs::remove(path,ec); ec.clear(); fs::rename(tmp,path,ec);} if(ec){error=ec.message();return false;} return true;
}
bool SignatureDb::contains(const std::string& sha256,std::string* label) const{auto it=labels_.find(sha256);if(it==labels_.end())return false;if(label)*label=it->second;return true;}
void SignatureDb::merge(const std::string& sha256,const std::string& label){if(sha256.size()==64)labels_[sha256]=label.empty()?"Known.Malware":label;}
}
