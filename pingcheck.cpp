// pingcheck.cpp - постоянный мониторинг компьютеров по списку (Windows)
// Сборка (MSVC):  cl /EHsc /std:c++17 /utf-8 pingcheck.cpp
// Сборка (MinGW): g++ -std=c++17 pingcheck.cpp -o pingcheck.exe -static
//
// Использование:
//   pingcheck.exe                  -> следит за файлом computers.txt
//   pingcheck.exe list.txt         -> следит за файлом list.txt
//   pingcheck.exe list.txt 5       -> интервал проверки 5 секунд (по умолчанию 3)
//   pingcheck.exe PC-001           -> один компьютер (если это не имя .txt файла)
//
// Файл перечитывается постоянно: добавили имя - оно сразу появилось,
// удалили - пропало. Проверка каждого компьютера идёт бесконечно.
//
//   +++  пингуется, IP из ping совпадает с nslookup
//   ###  пингуется, но IP не совпадает с nslookup (или нет записи в DNS)
//   ---  не пингуется

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// ---------- утилиты ----------

static std::string runCmd(const std::string& cmd) {
    std::string out;
    FILE* p = _popen((cmd + " 2>&1").c_str(), "r");
    if (!p) return out;
    char buf[512];
    while (fgets(buf, sizeof(buf), p)) out += buf;
    _pclose(p);
    return out;
}

static std::vector<std::string> splitLines(const std::string& s) {
    std::vector<std::string> lines;
    std::istringstream iss(s);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    return lines;
}

static std::string toUpper(std::string s) {
    for (auto& c : s) c = (char)std::toupper((unsigned char)c);
    return s;
}

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::string padRight(const std::string& s, size_t n) {
    return s.size() >= n ? s + " " : s + std::string(n - s.size(), ' ');
}

// Допустимы только безопасные символы (защита от внедрения команд).
static bool validHostname(const std::string& h) {
    if (h.empty() || h.size() > 253) return false;
    for (unsigned char c : h)
        if (!(std::isalnum(c) || c == '-' || c == '_' || c == '.')) return false;
    return true;
}

static bool isIPv4(const std::string& s) {
    int parts = 0;
    size_t i = 0;
    while (i < s.size()) {
        size_t j = i;
        while (j < s.size() && std::isdigit((unsigned char)s[j])) j++;
        if (j == i || j - i > 3) return false;
        if (std::stoi(s.substr(i, j - i)) > 255) return false;
        parts++;
        if (j == s.size()) break;
        if (s[j] != '.') return false;
        i = j + 1;
        if (i == s.size()) return false;
    }
    return parts == 4;
}

static std::vector<std::string> extractIPv4(const std::string& text) {
    std::vector<std::string> res;
    size_t i = 0;
    while (i < text.size()) {
        if (std::isdigit((unsigned char)text[i])) {
            size_t j = i;
            while (j < text.size() && (std::isdigit((unsigned char)text[j]) || text[j] == '.')) j++;
            std::string tok = text.substr(i, j - i);
            while (!tok.empty() && tok.back() == '.') tok.pop_back();
            if (isIPv4(tok)) res.push_back(tok);
            i = j;
        } else {
            i++;
        }
    }
    return res;
}

static std::string timeStr(std::time_t t) {
    if (!t) return "--:--:--";
    std::tm tm{};
    localtime_s(&tm, &t);
    char b[16];
    std::strftime(b, sizeof(b), "%H:%M:%S", &tm);
    return b;
}

// ---------- проверка одного компьютера ----------

static bool doPing(const std::string& host, std::string& ip) {
    std::string out = runCmd("ping -4 -n 2 -w 1000 " + host);
    for (const auto& line : splitLines(out)) {
        if (toUpper(line).find("TTL=") != std::string::npos) {
            auto ips = extractIPv4(line);
            if (!ips.empty()) {
                ip = ips[0];
                return true;
            }
        }
    }
    return false;
}

// Первый IP в выводе nslookup - это DNS-сервер, он пропускается.
static std::vector<std::string> doNslookup(const std::string& host) {
    std::string out = runCmd("nslookup " + host);
    auto ips = extractIPv4(out);
    if (ips.size() > 1) return std::vector<std::string>(ips.begin() + 1, ips.end());
    return {};
}

// ---------- состояние ----------

class Semaphore {
public:
    explicit Semaphore(int c) : n_(c) {}
    void acquire() {
        std::unique_lock<std::mutex> l(m_);
        cv_.wait(l, [&] { return n_ > 0; });
        --n_;
    }
    void release() {
        { std::lock_guard<std::mutex> l(m_); ++n_; }
        cv_.notify_one();
    }
private:
    std::mutex m_;
    std::condition_variable cv_;
    int n_;
};

static Semaphore g_sem(16);          // не больше 16 одновременных проверок
static std::atomic<bool> g_dirty{true};

struct Host {
    std::string name;
    std::atomic<bool> stop{false};
    std::mutex m;
    std::string status = "...";      // "+++", "###", "---", "...", "???"
    std::string ip;
    std::string note;
    std::time_t since = 0;
};

static void setResult(Host& h, const std::string& st, const std::string& ip, const std::string& note) {
    std::lock_guard<std::mutex> l(h.m);
    if (h.status != st) h.since = std::time(nullptr);
    if (h.status != st || h.ip != ip || h.note != note) g_dirty = true;
    h.status = st;
    h.ip = ip;
    h.note = note;
}

static void worker(std::shared_ptr<Host> h, int intervalSec) {
    while (!h->stop) {
        std::string ip;
        std::vector<std::string> dns;
        g_sem.acquire();
        bool alive = doPing(h->name, ip);
        if (alive && !h->stop) dns = doNslookup(h->name);
        g_sem.release();
        if (h->stop) break;

        if (!alive) {
            setResult(*h, "---", "", "");
        } else {
            bool match = std::find(dns.begin(), dns.end(), ip) != dns.end();
            std::string note;
            if (!match) {
                note = "DNS: ";
                if (dns.empty()) note += "нет записи";
                for (size_t i = 0; i < dns.size(); i++) note += (i ? "," : "") + dns[i];
            }
            setResult(*h, match ? "+++" : "###", ip, note);
        }
        for (int i = 0; i < intervalSec * 10 && !h->stop; i++)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// ---------- вывод в консоль (Unicode, поэтому кириллица без кракозябр) ----------

static HANDLE g_out;
static WORD g_defaultAttr = 7;

static void writeW(const std::string& utf8) {
    if (utf8.empty()) return;
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &w[0], n);
    DWORD written = 0;
    WriteConsoleW(g_out, w.c_str(), (DWORD)w.size(), &written, nullptr);
}

static void clearScreen() {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(g_out, &csbi);
    DWORD cells = (DWORD)csbi.dwSize.X * (DWORD)csbi.dwSize.Y;
    COORD home{0, 0};
    DWORD w = 0;
    FillConsoleOutputCharacterW(g_out, L' ', cells, home, &w);
    FillConsoleOutputAttribute(g_out, g_defaultAttr, cells, home, &w);
    SetConsoleCursorPosition(g_out, home);
}

static WORD colorFor(const std::string& s) {
    if (s == "+++") return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    if (s == "###") return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    if (s == "---") return FOREGROUND_RED | FOREGROUND_INTENSITY;
    return g_defaultAttr;
}

static void render(const std::vector<std::shared_ptr<Host>>& hosts, const std::string& src, bool fileMode, bool fileOk) {
    clearScreen();
    int ok = 0, bad = 0, down = 0;
    for (auto& h : hosts) {
        std::lock_guard<std::mutex> l(h->m);
        if (h->status == "+++") ok++;
        else if (h->status == "###") bad++;
        else if (h->status == "---") down++;
    }
    SetConsoleTextAttribute(g_out, g_defaultAttr);
    std::string head = "Мониторинг: " + src + "   (Ctrl+C - выход)\n";
    head += "Всего: " + std::to_string(hosts.size()) + "   +++ " + std::to_string(ok) +
            "   ### " + std::to_string(bad) + "   --- " + std::to_string(down) + "\n";
    if (fileMode && !fileOk) head += "Файл не найден - жду, пока он появится...\n";
    head += "\n";
    writeW(head);

    for (auto& h : hosts) {
        std::lock_guard<std::mutex> l(h->m);
        std::string line = h->status + "  " + padRight(h->name, 26) + padRight(h->ip, 16);
        if (h->status == "...") line += "проверка...";
        else if (h->status != "???") line += "с " + timeStr(h->since);
        if (!h->note.empty()) line += "  " + h->note;
        line += "\n";
        SetConsoleTextAttribute(g_out, colorFor(h->status));
        writeW(line);
    }
    SetConsoleTextAttribute(g_out, g_defaultAttr);
}

// ---------- чтение списка ----------

static bool loadList(const std::string& path, std::vector<std::string>& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    out.clear();
    std::string line;
    bool first = true;
    while (std::getline(in, line)) {
        if (first && line.compare(0, 3, "\xEF\xBB\xBF") == 0) line.erase(0, 3);  // BOM
        first = false;
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        for (char& c : line) if (c == ',' || c == '\t') c = ' ';
        std::istringstream iss(line);
        std::string name;
        while (iss >> name) {
            bool dup = false;
            for (auto& e : out) if (toUpper(e) == toUpper(name)) { dup = true; break; }
            if (!dup) out.push_back(name);
        }
    }
    return true;
}

static void syncHosts(std::vector<std::shared_ptr<Host>>& hosts, const std::vector<std::string>& names, int intervalSec) {
    std::vector<std::shared_ptr<Host>> next;
    for (const auto& n : names) {
        std::shared_ptr<Host> found;
        for (auto& h : hosts) if (toUpper(h->name) == toUpper(n)) { found = h; break; }
        if (!found) {
            found = std::make_shared<Host>();
            found->name = n;
            if (validHostname(n)) {
                std::thread(worker, found, intervalSec).detach();
            } else {
                found->status = "???";
                found->note = "недопустимое имя";
            }
        }
        next.push_back(found);
    }
    for (auto& h : hosts) {
        if (std::find(next.begin(), next.end(), h) == next.end()) h->stop = true;
    }
    hosts.swap(next);
    g_dirty = true;
}

static bool endsWithTxt(const std::string& s) {
    std::string u = toUpper(s);
    return u.size() >= 4 && u.compare(u.size() - 4, 4, ".TXT") == 0;
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(g_out, &csbi)) g_defaultAttr = csbi.wAttributes;

    std::string source = (argc > 1) ? argv[1] : "computers.txt";
    int interval = (argc > 2) ? std::atoi(argv[2]) : 3;
    if (interval < 1) interval = 3;

    bool fileMode = (argc == 1) || endsWithTxt(source) || std::ifstream(source).good();

    std::vector<std::shared_ptr<Host>> hosts;
    std::vector<std::string> names;
    bool fileOk = true;

    if (!fileMode) {
        names = {source};
        syncHosts(hosts, names, interval);
    }

    while (true) {
        if (fileMode) {
            std::vector<std::string> n;
            bool ok = loadList(source, n);
            if (ok != fileOk) { fileOk = ok; g_dirty = true; }
            if (ok && (n != names || (hosts.empty() && !n.empty()))) {
                names = n;
                syncHosts(hosts, names, interval);
            }
        }
        if (g_dirty.exchange(false)) render(hosts, source, fileMode, fileOk);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}
