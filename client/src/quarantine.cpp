#include "aegis/core.h"
#include <fstream>
#include <chrono>

namespace aegis {
bool Quarantine::quarantine(const fs::path& path,const std::string& sha,std::string& id,std::string& error){
    std::error_code ec; fs::create_directories(cfg_.quarantinePath,ec);
    auto now=std::chrono::system_clock::now().time_since_epoch().count(); id=sha.substr(0,16)+"_"+std::to_string(now);
    auto dst=cfg_.quarantinePath/to_wide(id+".q");
    fs::copy_file(path,dst,fs::copy_options::overwrite_existing,ec); if(ec){error="Quarantine copy failed: "+ec.message();return false;}
    std::ofstream m(cfg_.quarantinePath/to_wide(id+".meta")); m<<to_utf8(path.wstring())<<"\n"<<sha<<"\n"; m.close();
    fs::remove(path,ec); if(ec){error="Copied to quarantine but original could not be removed: "+ec.message();return false;}
    return true;
}
bool Quarantine::restore(const std::string& id,std::string& error){
    auto meta=cfg_.quarantinePath/to_wide(id+".meta"), q=cfg_.quarantinePath/to_wide(id+".q");
    std::ifstream m(meta);std::string orig,sha;if(!m||!std::getline(m,orig)||!std::getline(m,sha)){error="Metadata not found";return false;}
    fs::path dst=to_wide(orig);std::error_code ec;fs::create_directories(dst.parent_path(),ec);fs::copy_file(q,dst,fs::copy_options::overwrite_existing,ec);if(ec){error=ec.message();return false;}fs::remove(q,ec);fs::remove(meta,ec);return true;
}
std::vector<std::string> Quarantine::list() const{std::vector<std::string> out;std::error_code ec;if(!fs::exists(cfg_.quarantinePath))return out;for(auto& e:fs::directory_iterator(cfg_.quarantinePath,ec))if(e.path().extension()==L".meta")out.push_back(to_utf8(e.path().stem().wstring()));return out;}
}
