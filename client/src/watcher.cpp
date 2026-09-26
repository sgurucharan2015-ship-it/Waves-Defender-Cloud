#include "aegis/core.h"
#include <vector>
#include <thread>
#include <unordered_map>
#include <chrono>

namespace aegis {
void DirectoryWatcher::watch(const fs::path& dir,std::atomic_bool& stop,const std::function<void(const ScanResult&)>& cb){
    HANDLE h=CreateFileW(dir.c_str(),FILE_LIST_DIRECTORY,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr);
    if(h==INVALID_HANDLE_VALUE){log_line(cfg_,"Watcher cannot open "+to_utf8(dir.wstring()));return;}
    std::vector<BYTE> buffer(64*1024);std::unordered_map<std::wstring,std::chrono::steady_clock::time_point> recent;
    while(!stop){DWORD bytes=0;BOOL ok=ReadDirectoryChangesW(h,buffer.data(),(DWORD)buffer.size(),TRUE,FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_SIZE|FILE_NOTIFY_CHANGE_LAST_WRITE,&bytes,nullptr,nullptr);if(!ok)break;
        BYTE* ptr=buffer.data();for(;;){auto* n=(FILE_NOTIFY_INFORMATION*)ptr;std::wstring rel(n->FileName,n->FileNameLength/sizeof(wchar_t));fs::path p=dir/rel;
            if(n->Action==FILE_ACTION_ADDED||n->Action==FILE_ACTION_RENAMED_NEW_NAME||n->Action==FILE_ACTION_MODIFIED){auto now=std::chrono::steady_clock::now();auto it=recent.find(p.wstring());if(it==recent.end()||now-it->second>std::chrono::seconds(2)){recent[p.wstring()]=now;std::this_thread::sleep_for(std::chrono::milliseconds(250));std::error_code ec;if(fs::is_regular_file(p,ec))cb(scanner_->scan_file(p));}}
            if(!n->NextEntryOffset)break;ptr+=n->NextEntryOffset;}
    }CloseHandle(h);
}
}
