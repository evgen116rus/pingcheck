// pingcheck.cpp - проверка компьютеров по списку (Windows)
// Сборка (MSVC):  cl /EHsc /std:c++17 pingcheck.cpp
// Сборка (MinGW): g++ -std=c++17 pingcheck.cpp -o pingcheck.exe
//
// Использование:
//   pingcheck.exe                 -> читает computers.txt
//   pingcheck.exe list.txt        -> читает list.txt (по одному имени в строке)
//   pingcheck.exe PC-001          -> если файла PC-001 нет, это одно имя компьютера
//
// Результат:
//   +++  пингуется, IP из ping совпадает с nslookup и имя из nbtstat совпадает
//   ###  пингуется, но IP или имя не совпадают
//   ---  не пингуется

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// Если true - отсутствие ответа nbtstat (закрыт порт 137) считается несовпадением.
// Если false - в этом случае сравниваются только nslookup и ping.
static const bool STRICT_NBTSTAT = false;

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

// Допустимы только безопасные символы, чтобы имя нельзя было использовать для внедрения команд.
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

// Находит все IPv4-адреса в тексте.
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

// ping: возвращает true, если есть ответ; ip - адрес, с которого пришёл ответ.
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

// nslookup: IP-адреса имени (первый адрес в выводе - это DNS-сервер, он пропускается).
static std::vector<std::string> doNslookup(const std::string& host) {
    std::string out = runCmd("nslookup " + host);
    auto ips = extractIPv4(out);
    if (ips.size() > 1) return std::vector<std::string>(ips.begin() + 1, ips.end());
    return {};
}

// nbtstat -A ip: NetBIOS-имя компьютера (первая запись с <00>).
static std::string doNbtstat(const std::string& ip) {
    std::string out = runCmd("nbtstat -A " + ip);
    for (const auto& line : splitLines(out)) {
        if (line.find("<00>") != std::string::npos) {
            std::istringstream iss(line);
            std::string name;
            iss >> name;
            return name;
        }
    }
    return "";
}

static std::string shortName(const std::string& h) {
    size_t p = h.find('.');
    return toUpper(p == std::string::npos ? h : h.substr(0, p));
}

static std::string checkHost(const std::string& host) {
    if (!validHostname(host)) return "###  " + host + "  (недопустимое имя)";

    std::string pingIp;
    if (!doPing(host, pingIp)) return "---  " + host;

    auto dnsIps = doNslookup(host);
    bool dnsMatch = std::find(dnsIps.begin(), dnsIps.end(), pingIp) != dnsIps.end();

    std::string nbtName = doNbtstat(pingIp);
    bool nbtMatch;
    if (nbtName.empty()) nbtMatch = !STRICT_NBTSTAT;
    else nbtMatch = (toUpper(nbtName) == shortName(host));

    std::ostringstream res;
    res << (dnsMatch && nbtMatch ? "+++" : "###") << "  " << host << "  ping=" << pingIp;
    res << "  dns=";
    if (dnsIps.empty()) res << "нет";
    for (size_t i = 0; i < dnsIps.size(); i++) res << (i ? "," : "") << dnsIps[i];
    res << "  nbt=" << (nbtName.empty() ? "нет ответа" : nbtName);
    return res.str();
}

int main(int argc, char** argv) {
    std::string arg = (argc > 1) ? argv[1] : "computers.txt";
    std::vector<std::string> hosts;

    std::ifstream in(arg);
    if (in) {
        std::string line;
        while (std::getline(in, line)) {
            line = trim(line);
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;
            hosts.push_back(line);
        }
    } else if (argc > 1) {
        hosts.push_back(arg);  // не файл - значит одно имя компьютера
    } else {
        std::cerr << "Файл computers.txt не найден.\n";
        return 1;
    }

    std::ofstream log("result.txt");
    for (const auto& h : hosts) {
        std::string r = checkHost(h);
        std::cout << r << std::endl;
        if (log) log << r << "\n";
    }
    return 0;
}
