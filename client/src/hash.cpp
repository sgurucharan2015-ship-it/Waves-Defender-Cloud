#include "aegis/core.h"
#include <bcrypt.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#pragma comment(lib,"bcrypt.lib")

namespace aegis {
std::string sha256_file(const fs::path& path, std::string& error) {
    BCRYPT_ALG_HANDLE alg=nullptr; BCRYPT_HASH_HANDLE hash=nullptr;
    DWORD objLen=0,hashLen=0,cb=0;
    if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)!=0){error="BCryptOpenAlgorithmProvider failed";return{};}
    if(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&objLen,sizeof(objLen),&cb,0)!=0 ||
       BCryptGetProperty(alg,BCRYPT_HASH_LENGTH,(PUCHAR)&hashLen,sizeof(hashLen),&cb,0)!=0){error="BCryptGetProperty failed";BCryptCloseAlgorithmProvider(alg,0);return{};}
    std::vector<UCHAR> obj(objLen), digest(hashLen);
    if(BCryptCreateHash(alg,&hash,obj.data(),objLen,nullptr,0,0)!=0){error="BCryptCreateHash failed";BCryptCloseAlgorithmProvider(alg,0);return{};}
    std::ifstream f(path,std::ios::binary); if(!f){error="Cannot open file";BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(alg,0);return{};}
    std::vector<char> buf(1<<20);
    while(f){f.read(buf.data(),buf.size()); auto n=f.gcount(); if(n>0) BCryptHashData(hash,(PUCHAR)buf.data(),(ULONG)n,0);}
    if(BCryptFinishHash(hash,digest.data(),hashLen,0)!=0){error="BCryptFinishHash failed";BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(alg,0);return{};}
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg,0);
    std::ostringstream os; os<<std::hex<<std::setfill('0'); for(auto b:digest) os<<std::setw(2)<<(int)b;
    return os.str();
}
}
