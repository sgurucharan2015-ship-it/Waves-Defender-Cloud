#pragma once
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <functional>
#include <atomic>

namespace aegis {

namespace fs = std::filesystem;

enum class Verdict { Clean, Suspicious, Malicious, Error };

struct Finding {
    std::string name;
    int score{};
    std::string detail;
};

struct ScanResult {
    fs::path path;
    std::string sha256;
    Verdict verdict{Verdict::Error};
    int score{};
    std::string source;
    std::vector<Finding> findings;
    std::string error;
};

struct Config {
    std::wstring serverUrl = L"http://127.0.0.1:8787";
    std::wstring apiToken = L"change-me";
    bool onlineLookup = true;
    bool uploadUnknown = false;
    bool autoQuarantine = false;
    bool killMaliciousProcesses = false;
    size_t maxUploadBytes = 32ull * 1024 * 1024;
    size_t maxStaticReadBytes = 32ull * 1024 * 1024;
    std::vector<fs::path> watchPaths;
    fs::path signaturesPath;
    fs::path quarantinePath;
    fs::path logPath;

    static Config load(const fs::path& path = {});
};

std::string to_utf8(const std::wstring& s);
std::wstring to_wide(const std::string& s);
std::string verdict_string(Verdict v);
void log_line(const Config& cfg, const std::string& line);

std::string sha256_file(const fs::path& path, std::string& error);

class SignatureDb {
public:
    bool load(const fs::path& path, std::string& error);
    bool save(const fs::path& path, std::string& error) const;
    bool contains(const std::string& sha256, std::string* label = nullptr) const;
    size_t size() const { return labels_.size(); }
    void merge(const std::string& sha256, const std::string& label);
private:
    std::unordered_map<std::string, std::string> labels_;
};

struct HttpResponse {
    int status{};
    std::string body;
    std::unordered_map<std::string,std::string> headers;
    std::string error;
};

class HttpClient {
public:
    HttpResponse get(const std::wstring& url, const std::wstring& token = L"");
    HttpResponse post_binary(const std::wstring& url, const std::vector<unsigned char>& body,
                             const std::wstring& token, const std::wstring& filename);
};

class Quarantine {
public:
    explicit Quarantine(const Config& cfg): cfg_(cfg) {}
    bool quarantine(const fs::path& path, const std::string& sha256, std::string& id, std::string& error);
    bool restore(const std::string& id, std::string& error);
    std::vector<std::string> list() const;
private:
    Config cfg_;
};

class Scanner {
public:
    Scanner(Config cfg, SignatureDb* db);
    ScanResult scan_file(const fs::path& path, bool allowOnline = true);
    void scan_directory(const fs::path& root, const std::function<void(const ScanResult&)>& callback,
                        std::atomic_bool* stopFlag = nullptr);
    bool update_signatures(std::string& error);
private:
    Config cfg_;
    SignatureDb* db_{};
    HttpClient http_;
    void static_heuristics(const fs::path& path, const std::vector<unsigned char>& data, ScanResult& r);
    bool is_authenticode_signed(const fs::path& path);
    double entropy(const std::vector<unsigned char>& data);
};

class DirectoryWatcher {
public:
    DirectoryWatcher(Scanner* scanner, Config cfg): scanner_(scanner), cfg_(std::move(cfg)) {}
    void watch(const fs::path& dir, std::atomic_bool& stopFlag,
               const std::function<void(const ScanResult&)>& callback);
private:
    Scanner* scanner_{};
    Config cfg_;
};

class ProcessMonitor {
public:
    ProcessMonitor(Scanner* scanner, Config cfg): scanner_(scanner), cfg_(std::move(cfg)) {}
    void run(std::atomic_bool& stopFlag, const std::function<void(const ScanResult&)>& callback);
private:
    Scanner* scanner_{};
    Config cfg_;
};

bool install_service(const fs::path& exePath, std::string& error);
bool uninstall_service(std::string& error);
int run_service();

}
