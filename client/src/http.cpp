#include "aegis/core.h"
#include <winhttp.h>
#include <vector>
#pragma comment(lib,"winhttp.lib")

namespace aegis {
struct Parts{std::wstring host,path; INTERNET_PORT port{}; bool secure{};};
static bool split_url(const std::wstring& u,Parts& p){
    URL_COMPONENTS c{}; c.dwStructSize=sizeof(c); c.dwHostNameLength=(DWORD)-1;c.dwUrlPathLength=(DWORD)-1;c.dwExtraInfoLength=(DWORD)-1;
    if(!WinHttpCrackUrl(u.c_str(),0,0,&c)) return false;
    p.host.assign(c.lpszHostName,c.dwHostNameLength); p.path.assign(c.lpszUrlPath,c.dwUrlPathLength); if(c.dwExtraInfoLength) p.path.append(c.lpszExtraInfo,c.dwExtraInfoLength);
    p.port=c.nPort; p.secure=c.nScheme==INTERNET_SCHEME_HTTPS; return true;
}
static HttpResponse send_req(const std::wstring& method,const std::wstring& url,const std::wstring& token,const void* body,DWORD bodyLen,const std::wstring& contentType,const std::wstring& filename){
    HttpResponse out; Parts p; if(!split_url(url,p)){out.error="Bad URL";return out;}
    HINTERNET s=WinHttpOpen(L"AegisAV/1.0",WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0); if(!s){out.error="WinHttpOpen failed";return out;}
    HINTERNET c=WinHttpConnect(s,p.host.c_str(),p.port,0); if(!c){out.error="WinHttpConnect failed";WinHttpCloseHandle(s);return out;}
    DWORD flags=p.secure?WINHTTP_FLAG_SECURE:0; HINTERNET r=WinHttpOpenRequest(c,method.c_str(),p.path.c_str(),nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,flags);
    if(!r){out.error="WinHttpOpenRequest failed";WinHttpCloseHandle(c);WinHttpCloseHandle(s);return out;}
    std::wstring hdr;
    if(!token.empty()) hdr+=L"X-Aegis-Token: "+token+L"\r\n";
    if(!contentType.empty()) hdr+=L"Content-Type: "+contentType+L"\r\n";
    if(!filename.empty()) hdr+=L"X-File-Name: "+filename+L"\r\n";
    BOOL ok=WinHttpSendRequest(r,hdr.empty()?WINHTTP_NO_ADDITIONAL_HEADERS:hdr.c_str(),(DWORD)-1L,(LPVOID)body,bodyLen,bodyLen,0);
    if(ok) ok=WinHttpReceiveResponse(r,nullptr);
    if(!ok){out.error="HTTP request failed: "+std::to_string(GetLastError());WinHttpCloseHandle(r);WinHttpCloseHandle(c);WinHttpCloseHandle(s);return out;}
    DWORD sc=0,sz=sizeof(sc); WinHttpQueryHeaders(r,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&sc,&sz,WINHTTP_NO_HEADER_INDEX); out.status=(int)sc;
    for(;;){DWORD avail=0;if(!WinHttpQueryDataAvailable(r,&avail)||!avail)break;std::string buf(avail,'\0');DWORD got=0;if(!WinHttpReadData(r,buf.data(),avail,&got))break;buf.resize(got);out.body+=buf;}
    WinHttpCloseHandle(r);WinHttpCloseHandle(c);WinHttpCloseHandle(s);return out;
}
HttpResponse HttpClient::get(const std::wstring& url,const std::wstring& token){return send_req(L"GET",url,token,nullptr,0,L"",L"");}
HttpResponse HttpClient::post_binary(const std::wstring& url,const std::vector<unsigned char>& body,const std::wstring& token,const std::wstring& filename){return send_req(L"POST",url,token,body.data(),(DWORD)body.size(),L"application/octet-stream",filename);}
}
