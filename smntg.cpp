#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <direct.h>
#include <io.h>
#include <ctime>
#include <memory>
#include <sqlite3.h>

using namespace std;

// ================================================
// WINDOWS CRITICAL SECTION WRAPPER
// ================================================

class CriticalSection {
private:
    CRITICAL_SECTION cs;
public:
    CriticalSection()  { InitializeCriticalSection(&cs); }
    ~CriticalSection() { DeleteCriticalSection(&cs); }
    void lock()   { EnterCriticalSection(&cs); }
    void unlock() { LeaveCriticalSection(&cs); }
};

class ScopedLock {
private:
    CriticalSection& cs;
public:
    ScopedLock(CriticalSection& c) : cs(c) { cs.lock(); }
    ~ScopedLock() { cs.unlock(); }
};

// ================================================
// FILESYSTEM COMPATIBILITY
// ================================================

namespace fs_compat {

    bool exists(const string& path) {
        return _access(path.c_str(), 0) == 0;
    }

    bool create_directories(const string& path) {
        if (path.empty()) return false;
        string p = path;
        for (char& c : p) if (c == '/') c = '\\';

        bool hadTrailing = false;
        if (!p.empty() && (p.back() == '\\' || p.back() == '/')) {
            hadTrailing = true;
            p.pop_back();
        }

        string current;
        size_t start = 0;
        if (p.size() >= 2 && isalpha((unsigned char)p[0]) && p[1] == ':') {
            current = p.substr(0, 2);
            start = 2;
            if (p.size() > 2 && p[2] == '\\') {
                current += '\\';
                start = 3;
            }
        } else if (p.size() >= 2 && p[0] == '\\' && p[1] == '\\') {
            current = "\\\\";
            start = 2;
        }

        while (start <= p.size()) {
            size_t pos = p.find('\\', start);
            string token;
            if (pos == string::npos) {
                token = p.substr(start);
                start = p.size() + 1;
            } else {
                token = p.substr(start, pos - start);
                start = pos + 1;
            }
            if (!token.empty()) {
                if (!current.empty() && current.back() != '\\') current += '\\';
                current += token;
            }
            if (!current.empty() && !exists(current)) {
                if (_mkdir(current.c_str()) != 0) {
                    if (errno != EEXIST) return false;
                }
            }
            if (pos == string::npos) break;
        }

        if (hadTrailing) {
            if (!exists(path) && _mkdir(path.c_str()) != 0 && errno != EEXIST) return false;
        }
        return true;
    }

    bool remove(const string& path) {
        return DeleteFileA(path.c_str()) != 0;
    }

    vector<string> directory_iterator(const string& path) {
        vector<string> files;
        WIN32_FIND_DATAA findData;
        string normalized = path;
        for (char& c : normalized) if (c == '/') c = '\\';
        if (!normalized.empty() && normalized.back() == '\\') normalized.pop_back();
        string searchPath = normalized + "\\*";

        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) return files;

        do {
            string name = findData.cFileName;
            if (name == "." || name == "..") continue;
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            files.push_back(normalized + "\\" + name);
        } while (FindNextFileA(hFind, &findData));

        FindClose(hFind);
        return files;
    }
}

// ================================================
// FILE MANAGER
// ================================================

class FileManager {
public:
    static bool readFile(const string& filename, vector<unsigned char>& outData) {
        ifstream file(filename.c_str(), ios::binary | ios::ate);
        if (!file) return false;
        streamsize size = file.tellg();
        if (size < 0 || size > 50 * 1024 * 1024) return false;
        file.seekg(0, ios::beg);
        outData.resize(static_cast<size_t>(size));
        if (size > 0 && !file.read(reinterpret_cast<char*>(&outData[0]), size))
            return false;
        return true;
    }

    static bool writeFile(const string& filename, const vector<unsigned char>& data) {
        ofstream file(filename.c_str(), ios::binary | ios::trunc);
        if (!file) return false;
        if (!data.empty() && !file.write(reinterpret_cast<const char*>(&data[0]), data.size()))
            return false;
        file.close();
        return file.good();
    }

    static vector<string> getFilesInDirectory(const string& directory) {
        return fs_compat::directory_iterator(directory);
    }

    static bool createDirectory(const string& path) {
        return fs_compat::create_directories(path);
    }

    static bool exists(const string& path) {
        return fs_compat::exists(path);
    }

    static bool removeFile(const string& path) {
        return fs_compat::remove(path);
    }

    static string generateTempFilename(const string& extension = ".pdf") {
        stringstream ss;
        ss << "temp_" << GetCurrentProcessId()
           << "_" << GetTickCount()
           << "_" << (rand() % 10000)
           << extension;
        return ss.str();
    }
};

// ================================================
// TYPES & ENUMS
// ================================================

enum CrashSeverity {
    SEV_NORMAL,
    SEV_LOAD_ERROR,
    SEV_ABNORMAL,
    SEV_EXCEPTION,
    SEV_REAL_CRASH,
    SEV_TIMEOUT
};

enum FuzzResult {
    NORMAL = 0,
    CRASH_DETECTED = 1,
    TIMEOUT = 2,
    INVALID_INPUT = 3,
    HARNESS_ERROR = 4,
    LOAD_ERROR_DETECTED = 5
};

struct CrashData {
    vector<unsigned char> triggeringInput;
    string seedFilename;
    string crashType;
    size_t crashAddress;
    string stackTrace;
    time_t timestamp;
    size_t iterationNumber;
    DWORD exitCode;
    string filename;
    size_t inputSize;
    string mutatorUsed;
    CrashSeverity severity;
    bool isMalicious;
    vector<string> maliciousKeys;

    CrashData() : crashAddress(0), timestamp(0), iterationNumber(0),
                  exitCode(0), inputSize(0), severity(SEV_NORMAL), isMalicious(false) {}
};

struct FuzzingStats {
    size_t totalIterations;
    size_t totalCrashes;
    size_t totalLoadErrors;
    size_t totalMalicious;
    size_t totalTimeouts;
    size_t totalErrors;
    time_t startTime;
    time_t endTime;
    double executionRate;
};

struct Config {
    string executablePath;
    unsigned int timeoutMs;
    string seedDirectory;
    string outputDirectory;
    string crashDirectory;
    string logFile;
    string statsFile;
    string databaseFile;
    size_t maxInputSize;
    bool saveLoadErrors;

    Config() {
        const char* possiblePaths[] = {
            "C:\\Program Files\\SumatraPDF\\SumatraPDF.exe",
            "C:\\Program Files (x86)\\SumatraPDF\\SumatraPDF.exe",
            "C:\\Program Files\\SumatraPDF\\SumatraPDF-3.5.2-64.exe",
            "sumatrapdf.exe",
            ".\\SumatraPDF.exe"
        };

        for (const char* path : possiblePaths) {
            if (FileManager::exists(path)) {
                executablePath = path;
                cout << "[INFO] Found SumatraPDF at: " << path << endl;
                break;
            }
        }

        if (executablePath.empty()) {
            executablePath = "C:\\Program Files\\SumatraPDF\\SumatraPDF.exe";
            cout << "[WARNING] Using default path: " << executablePath << endl;
        }

        timeoutMs       = 5000;
        seedDirectory   = ".\\inputs\\seeds\\";
        outputDirectory = ".\\outputs\\";
        crashDirectory  = ".\\outputs\\crashes\\";
        logFile         = ".\\outputs\\fuzzing.log";
        statsFile       = ".\\outputs\\fuzzing_stats.txt";
        databaseFile    = ".\\outputs\\fuzzing.db";
        maxInputSize    = 10 * 1024 * 1024;
        saveLoadErrors  = false;
    }
};

// ================================================
// DATABASE MANAGER
// ================================================

class DatabaseManager {
private:
    sqlite3* db;
    CriticalSection dbMutex;
    string dbPath;

public:
    DatabaseManager() : db(nullptr) {}

    ~DatabaseManager() {
        if (db) sqlite3_close(db);
    }

    bool initialize(const string& databasePath) {
        dbPath = databasePath;
        size_t lastSlash = databasePath.find_last_of("\\/");
        if (lastSlash != string::npos)
            FileManager::createDirectory(databasePath.substr(0, lastSlash));

        int rc = sqlite3_open(databasePath.c_str(), &db);
        if (rc) {
            cerr << "[ERROR] Can't open database: " << sqlite3_errmsg(db) << endl;
            return false;
        }
        cout << "[INFO] Database opened: " << databasePath << endl;

        const char* dropSQL = "DROP TABLE IF EXISTS crashes; DROP TABLE IF EXISTS sessions;";
        char* dropErr = nullptr;
        sqlite3_exec(db, dropSQL, nullptr, nullptr, &dropErr);
        if (dropErr) sqlite3_free(dropErr);

        const char* createCrashTableSQL =
            "CREATE TABLE IF NOT EXISTS crashes ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "timestamp INTEGER NOT NULL,"
            "iteration INTEGER NOT NULL,"
            "crash_type TEXT NOT NULL,"
            "severity TEXT NOT NULL,"
            "exit_code INTEGER NOT NULL,"
            "filename TEXT NOT NULL,"
            "input_size INTEGER NOT NULL,"
            "mutator_used TEXT NOT NULL,"
            "is_malicious INTEGER DEFAULT 0,"
            "malicious_keys TEXT,"
            "crash_data BLOB,"
            "human_time TEXT"
            ");";

        const char* createSessionTableSQL =
            "CREATE TABLE IF NOT EXISTS sessions ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "start_time INTEGER NOT NULL,"
            "end_time INTEGER NOT NULL,"
            "total_iterations INTEGER NOT NULL,"
            "total_crashes INTEGER NOT NULL,"
            "total_load_errors INTEGER NOT NULL,"
            "total_malicious INTEGER NOT NULL,"
            "total_timeouts INTEGER NOT NULL,"
            "total_errors INTEGER NOT NULL,"
            "execution_rate REAL NOT NULL,"
            "human_start_time TEXT,"
            "human_end_time TEXT"
            ");";

        char* errorMsg = nullptr;

        rc = sqlite3_exec(db, createCrashTableSQL, nullptr, nullptr, &errorMsg);
        if (rc != SQLITE_OK) {
            cerr << "[ERROR] SQL error (crashes): " << errorMsg << endl;
            sqlite3_free(errorMsg);
            return false;
        }

        rc = sqlite3_exec(db, createSessionTableSQL, nullptr, nullptr, &errorMsg);
        if (rc != SQLITE_OK) {
            cerr << "[ERROR] SQL error (sessions): " << errorMsg << endl;
            sqlite3_free(errorMsg);
            return false;
        }

        cout << "[INFO] Database tables ready." << endl;
        return true;
    }

    static string severityToString(CrashSeverity sev) {
        switch (sev) {
            case SEV_REAL_CRASH:  return "REAL_CRASH";
            case SEV_EXCEPTION:   return "EXCEPTION";
            case SEV_LOAD_ERROR:  return "LOAD_ERROR";
            case SEV_ABNORMAL:    return "ABNORMAL";
            case SEV_TIMEOUT:     return "TIMEOUT";
            default:              return "NORMAL";
        }
    }

    bool saveCrash(const CrashData& crashData) {
        ScopedLock lock(dbMutex);

        const char* insertSQL =
            "INSERT INTO crashes "
            "(timestamp, iteration, crash_type, severity, exit_code, filename, "
            " input_size, mutator_used, is_malicious, malicious_keys, crash_data, human_time) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, insertSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            cerr << "[ERROR] Prepare failed: " << sqlite3_errmsg(db) << endl;
            return false;
        }

        string keysJoined;
        for (size_t i = 0; i < crashData.maliciousKeys.size(); i++) {
            if (i > 0) keysJoined += ", ";
            keysJoined += crashData.maliciousKeys[i];
        }

        sqlite3_bind_int64(stmt, 1,  crashData.timestamp);
        sqlite3_bind_int  (stmt, 2,  static_cast<int>(crashData.iterationNumber));
        sqlite3_bind_text (stmt, 3,  crashData.crashType.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 4,  severityToString(crashData.severity).c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int  (stmt, 5,  crashData.exitCode);
        sqlite3_bind_text (stmt, 6,  crashData.filename.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int  (stmt, 7,  static_cast<int>(crashData.inputSize));
        sqlite3_bind_text (stmt, 8,  crashData.mutatorUsed.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int  (stmt, 9,  crashData.isMalicious ? 1 : 0);
        sqlite3_bind_text (stmt, 10, keysJoined.c_str(), -1, SQLITE_TRANSIENT);

        if (!crashData.triggeringInput.empty()) {
            sqlite3_bind_blob(stmt, 11,
                crashData.triggeringInput.data(),
                static_cast<int>(crashData.triggeringInput.size()),
                SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt, 11);
        }

        char timeBuffer[64];
        struct tm* timeinfo = localtime(&crashData.timestamp);
        strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        sqlite3_bind_text(stmt, 12, timeBuffer, -1, SQLITE_TRANSIENT);

        rc = sqlite3_step(stmt);
        bool success = (rc == SQLITE_DONE);
        if (!success)
            cerr << "[ERROR] Insert failed: " << sqlite3_errmsg(db) << endl;

        sqlite3_finalize(stmt);
        return success;
    }

    bool saveSessionStats(const FuzzingStats& stats) {
        ScopedLock lock(dbMutex);

        const char* insertSQL =
            "INSERT INTO sessions "
            "(start_time, end_time, total_iterations, total_crashes, total_load_errors, "
            " total_malicious, total_timeouts, total_errors, execution_rate, "
            " human_start_time, human_end_time) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, insertSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            cerr << "[ERROR] Prepare failed: " << sqlite3_errmsg(db) << endl;
            return false;
        }

        char startBuf[64], endBuf[64];
        struct tm* si = localtime(&stats.startTime);
        struct tm* ei = localtime(&stats.endTime);
        strftime(startBuf, sizeof(startBuf), "%Y-%m-%d %H:%M:%S", si);
        strftime(endBuf,   sizeof(endBuf),   "%Y-%m-%d %H:%M:%S", ei);

        sqlite3_bind_int64 (stmt, 1,  stats.startTime);
        sqlite3_bind_int64 (stmt, 2,  stats.endTime);
        sqlite3_bind_int   (stmt, 3,  static_cast<int>(stats.totalIterations));
        sqlite3_bind_int   (stmt, 4,  static_cast<int>(stats.totalCrashes));
        sqlite3_bind_int   (stmt, 5,  static_cast<int>(stats.totalLoadErrors));
        sqlite3_bind_int   (stmt, 6,  static_cast<int>(stats.totalMalicious));
        sqlite3_bind_int   (stmt, 7,  static_cast<int>(stats.totalTimeouts));
        sqlite3_bind_int   (stmt, 8,  static_cast<int>(stats.totalErrors));
        sqlite3_bind_double(stmt, 9,  stats.executionRate);
        sqlite3_bind_text  (stmt, 10, startBuf, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text  (stmt, 11, endBuf,   -1, SQLITE_TRANSIENT);

        rc = sqlite3_step(stmt);
        bool success = (rc == SQLITE_DONE);
        if (!success)
            cerr << "[ERROR] Insert failed: " << sqlite3_errmsg(db) << endl;

        sqlite3_finalize(stmt);
        return success;
    }

    void printRecentCrashes(int limit = 10) {
        ScopedLock lock(dbMutex);

        const char* querySQL =
            "SELECT human_time, iteration, crash_type, severity, exit_code, "
            "       filename, input_size, is_malicious "
            "FROM crashes ORDER BY id DESC LIMIT ?;";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, querySQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            cerr << "[ERROR] Query prepare failed: " << sqlite3_errmsg(db) << endl;
            return;
        }
        sqlite3_bind_int(stmt, 1, limit);

        cout << "\n=== RECENT CRASHES FROM DATABASE ===" << endl;
        cout << left
             << setw(20) << "Timestamp"
             << setw(10) << "Iter"
             << setw(20) << "Crash Type"
             << setw(14) << "Severity"
             << setw(12) << "Exit Code"
             << setw(10) << "Malicious"
             << setw(10) << "Size" << endl;
        cout << string(96, '-') << endl;

        int count = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* ts  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            int  iter       = sqlite3_column_int(stmt, 1);
            const char* ct  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            const char* sev = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            int  ec         = sqlite3_column_int(stmt, 4);
            const char* fn  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            int  sz         = sqlite3_column_int(stmt, 6);
            int  mal        = sqlite3_column_int(stmt, 7);

            string crashType(ct ? ct : "");
            string severity(sev ? sev : "");
            string filename(fn ? fn : "");

            if (crashType.length() > 18) crashType = crashType.substr(0, 18) + "..";
            if (filename.length()  > 18) filename  = filename.substr(0, 18)  + "..";

            cout << left
                 << setw(20) << (ts ? ts : "")
                 << setw(10) << iter
                 << setw(20) << crashType
                 << setw(14) << severity
                 << setw(12) << ec
                 << setw(10) << (mal ? "YES ***" : "no")
                 << setw(10) << sz << endl;
            count++;
        }

        if (count == 0)
            cout << "[INFO] No crashes in database yet." << endl;

        sqlite3_finalize(stmt);
    }

    int getTotalCrashes() {
        ScopedLock lock(dbMutex);
        const char* sql = "SELECT COUNT(*) FROM crashes WHERE severity IN ('REAL_CRASH','EXCEPTION','LOAD_ERROR');";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return 0;
        int count = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return count;
    }

    int getTotalMalicious() {
        ScopedLock lock(dbMutex);
        const char* sql = "SELECT COUNT(*) FROM crashes WHERE is_malicious=1;";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return 0;
        int count = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return count;
    }
};

// ================================================
// STATS MANAGER
// ================================================

class StatsManager {
private:
    string statsFile;
    CriticalSection statsMutex;
    DatabaseManager* dbManager;

    string timeToString(time_t timestamp) {
        char buffer[20];
        struct tm* ti = localtime(&timestamp);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", ti);
        return string(buffer);
    }

public:
    StatsManager(const string& filename) : statsFile(filename), dbManager(nullptr) {}

    void setDatabaseManager(DatabaseManager* db) { dbManager = db; }

    bool initialize() {
        size_t slash = statsFile.find_last_of("\\/");
        if (slash != string::npos)
            FileManager::createDirectory(statsFile.substr(0, slash));
        return true;
    }

    bool saveCrash(const CrashData& crashData) {
        ScopedLock lock(statsMutex);
        ofstream file(statsFile.c_str(), ios::app);
        if (!file.is_open()) return false;
        file << "CRASH|" << crashData.timestamp
             << "|" << crashData.iterationNumber
             << "|" << crashData.crashType
             << "|" << DatabaseManager::severityToString(crashData.severity)
             << "|" << crashData.exitCode
             << "|" << crashData.filename
             << "|" << crashData.inputSize
             << "|" << crashData.mutatorUsed
             << "|" << (crashData.isMalicious ? "1" : "0") << endl;
        file.close();
        if (dbManager) return dbManager->saveCrash(crashData);
        return true;
    }

    bool saveSessionStats(const FuzzingStats& stats) {
        ScopedLock lock(statsMutex);
        ofstream file(statsFile.c_str(), ios::app);
        if (!file.is_open()) return false;
        file << "SESSION|" << stats.startTime
             << "|" << stats.endTime
             << "|" << stats.totalIterations
             << "|" << stats.totalCrashes
             << "|" << stats.totalLoadErrors
             << "|" << stats.totalMalicious
             << "|" << stats.totalTimeouts
             << "|" << stats.totalErrors
             << "|" << stats.executionRate << endl;
        file.close();
        if (dbManager) return dbManager->saveSessionStats(stats);
        return true;
    }

    void printRecentCrashes(int limit = 10) {
        ScopedLock lock(statsMutex);
        if (dbManager) { dbManager->printRecentCrashes(limit); return; }
        cout << "[INFO] No database manager available." << endl;
    }
};

// ================================================
// LOGGER
// ================================================

class Logger {
public:
    virtual void logInfo(const string& message) = 0;
    virtual void logError(const string& message) = 0;
    virtual void logCrash(const CrashData& crashData) = 0;
    virtual void logLoadError(const CrashData& crashData) = 0;
    virtual void flush() = 0;
    virtual ~Logger() {}
};

class CrashLogger : public Logger {
private:
    string crashDirectory;
    string loadErrorDirectory;
    string logFile;
    ofstream logStream;
    size_t crashCount;
    size_t loadErrorCount;
    CriticalSection logMutex;
    StatsManager* statsManager;
    bool saveLoadErrors;

    string getTimestamp() {
        time_t now = time(NULL);
        char buf[32];
        struct tm* ti = localtime(&now);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", ti);
        return string(buf);
    }

public:
    CrashLogger() : crashCount(0), loadErrorCount(0),
                    statsManager(nullptr), saveLoadErrors(false) {}

    ~CrashLogger() { if (logStream.is_open()) logStream.close(); }

    void setStatsManager(StatsManager* stats) { statsManager = stats; }

    bool initialize(const Config& config) {
        crashDirectory     = config.crashDirectory;
        saveLoadErrors     = config.saveLoadErrors;
        loadErrorDirectory = config.outputDirectory + "load_errors\\";
        logFile            = config.logFile;

        FileManager::createDirectory(crashDirectory);
        if (saveLoadErrors) FileManager::createDirectory(loadErrorDirectory);

        size_t lastSlash = logFile.find_last_of("\\/");
        if (lastSlash != string::npos)
            FileManager::createDirectory(logFile.substr(0, lastSlash));

        logStream.open(logFile.c_str(), ios::app);
        if (!logStream.is_open()) {
            cerr << "[ERROR] Could not open log file: " << logFile << endl;
            return false;
        }
        return true;
    }

    void logInfo(const string& message) {
        ScopedLock lock(logMutex);
        string ts = getTimestamp();
        if (logStream.is_open()) { logStream << "[" << ts << "] [INFO] " << message << endl; logStream.flush(); }
        cout << "[INFO] " << message << endl;
    }

    void logError(const string& message) {
        ScopedLock lock(logMutex);
        string ts = getTimestamp();
        if (logStream.is_open()) { logStream << "[" << ts << "] [ERROR] " << message << endl; logStream.flush(); }
        cerr << "[ERROR] " << message << endl;
    }

    void logCrash(const CrashData& crashData) {
        ScopedLock lock(logMutex);
        crashCount++;

        string dir = crashDirectory;
        if (!dir.empty() && dir.back() != '\\' && dir.back() != '/') dir += '\\';
        FileManager::createDirectory(dir);

        string origName = crashData.seedFilename;
        size_t slash = origName.find_last_of("\\/");
        if (slash != string::npos) origName = origName.substr(slash + 1);
        size_t dot = origName.find_last_of('.');
        if (dot != string::npos) origName = origName.substr(0, dot);

        stringstream ss;
        ss << origName
           << "_" << DatabaseManager::severityToString(crashData.severity)
           << (crashData.isMalicious ? "_MALICIOUS" : "")
           << "_iter" << crashData.iterationNumber << ".pdf";
        string crashFilePath = dir + ss.str();

        bool saved = FileManager::writeFile(crashFilePath, crashData.triggeringInput);

        if (saved) {
            CrashData updated = crashData;
            updated.filename  = crashFilePath;
            updated.inputSize = crashData.triggeringInput.size();

            string ts = getTimestamp();
            if (logStream.is_open()) {
                logStream << "[" << ts << "] [CRASH #" << crashCount << "] "
                          << crashData.crashType
                          << " | Severity: " << DatabaseManager::severityToString(crashData.severity)
                          << " | Malicious: " << (crashData.isMalicious ? "YES" : "no")
                          << " | ExitCode: 0x" << hex << uppercase << crashData.exitCode << dec
                          << " | File: " << crashFilePath
                          << " | Size: " << crashData.triggeringInput.size() << " bytes" << endl;
                logStream.flush();
            }

            if (statsManager) statsManager->saveCrash(updated);

            cout << "\n" << string(60, '=') << endl;
            cout << "  *** CRASH #" << crashCount << " DETECTED ***" << endl;
            cout << string(60, '=') << endl;
            cout << "  Severity : " << DatabaseManager::severityToString(crashData.severity) << endl;
            cout << "  Type     : " << crashData.crashType << endl;
            cout << "  Exit Code: 0x" << hex << uppercase << crashData.exitCode << dec << endl;
            cout << "  Malicious: " << (crashData.isMalicious ? "YES  <-- dangerous PDF structures!" : "no") << endl;
            if (crashData.isMalicious && !crashData.maliciousKeys.empty()) {
                cout << "  Keys     : ";
                for (size_t i = 0; i < crashData.maliciousKeys.size(); i++) {
                    if (i > 0) cout << ", ";
                    cout << crashData.maliciousKeys[i];
                }
                cout << endl;
            }
            cout << "  Mutator  : " << crashData.mutatorUsed << endl;
            cout << "  Size     : " << crashData.triggeringInput.size() << " bytes" << endl;
            cout << "  Saved to : " << crashFilePath << endl;
            cout << string(60, '=') << "\n" << endl;
        } else {
            cerr << "[ERROR] Failed to save crash file: " << crashFilePath << endl;
        }
    }

    void logLoadError(const CrashData& crashData) {
        ScopedLock lock(logMutex);
        loadErrorCount++;

        cout << "[LOAD_ERROR #" << loadErrorCount << "] "
             << "SumatraPDF rejected PDF at iter " << crashData.iterationNumber
             << (crashData.isMalicious ? " [MALICIOUS CONTENT]" : "") << endl;

        if (crashData.isMalicious && !crashData.maliciousKeys.empty()) {
            cout << "   Keys: ";
            for (size_t i = 0; i < crashData.maliciousKeys.size(); i++) {
                if (i > 0) cout << ", ";
                cout << crashData.maliciousKeys[i];
            }
            cout << endl;
        }

        string dir = crashDirectory;
        if (!dir.empty() && dir.back() != '\\' && dir.back() != '/') dir += '\\';
        FileManager::createDirectory(dir);

        string origName = crashData.seedFilename;
        size_t slash = origName.find_last_of("\\/");
        if (slash != string::npos) origName = origName.substr(slash + 1);
        size_t dot = origName.find_last_of('.');
        if (dot != string::npos) origName = origName.substr(0, dot);

        stringstream ss;
        ss << origName
           << (crashData.isMalicious ? "_MALICIOUS" : "")
           << "_LOAD_ERROR_iter" << crashData.iterationNumber << ".pdf";
        string filePath = dir + ss.str();

        bool saved = FileManager::writeFile(filePath, crashData.triggeringInput);
        if (saved) {
            cout << "   Saved to: " << filePath << endl;
            if (logStream.is_open()) {
                logStream << "[" << getTimestamp() << "] [LOAD_ERROR #" << loadErrorCount << "] "
                          << (crashData.isMalicious ? "MALICIOUS " : "")
                          << "File: " << filePath
                          << " | ExitCode=1 | Size=" << crashData.triggeringInput.size() << " bytes" << endl;
                logStream.flush();
            }
            CrashData updated = crashData;
            updated.filename  = filePath;
            updated.inputSize = crashData.triggeringInput.size();
            if (statsManager) statsManager->saveCrash(updated);
        } else {
            cerr << "[ERROR] Could not save load error file: " << filePath << endl;
        }
    }

    void flush() {
        ScopedLock lock(logMutex);
        if (logStream.is_open()) logStream.flush();
    }

    size_t getCrashCount()     const { return crashCount; }
    size_t getLoadErrorCount() const { return loadErrorCount; }
};

// ================================================
// MUTATORS
// ================================================

class Mutator {
public:
    virtual bool mutate(vector<unsigned char>& data) = 0;
    virtual string getName() const = 0;
    virtual ~Mutator() {}
};

class BitFlipMutator : public Mutator {
public:
    bool mutate(vector<unsigned char>& data) {
        if (data.empty()) return false;
        size_t bitPos  = rand() % (data.size() * 8);
        size_t bytePos = bitPos / 8;
        size_t bit     = bitPos % 8;
        data[bytePos] ^= (1 << bit);
        return true;
    }
    string getName() const { return "BitFlip"; }
};

class ByteFlipMutator : public Mutator {
public:
    bool mutate(vector<unsigned char>& data) {
        if (data.empty()) return false;
        size_t pos = rand() % data.size();
        data[pos]  = static_cast<unsigned char>(rand() % 256);
        return true;
    }
    string getName() const { return "ByteFlip"; }
};

class InsertBytesMutator : public Mutator {
public:
    bool mutate(vector<unsigned char>& data) {
        if (data.size() > 10 * 1024 * 1024) return false;
        size_t insertPos   = rand() % (data.size() + 1);
        size_t insertCount = 1 + (rand() % 16);
        for (size_t i = 0; i < insertCount && data.size() < 10 * 1024 * 1024; i++)
            data.insert(data.begin() + insertPos, static_cast<unsigned char>(rand() % 256));
        return true;
    }
    string getName() const { return "InsertBytes"; }
};

class DeleteBytesMutator : public Mutator {
public:
    bool mutate(vector<unsigned char>& data) {
        if (data.size() <= 1) return false;
        size_t deleteCount = 1 + (rand() % min(data.size() / 2, static_cast<size_t>(16)));
        size_t deletePos   = rand() % (data.size() - deleteCount + 1);
        data.erase(data.begin() + deletePos, data.begin() + deletePos + deleteCount);
        return true;
    }
    string getName() const { return "DeleteBytes"; }
};

class MagicNumberMutator : public Mutator {
public:
    bool mutate(vector<unsigned char>& data) {
        if (data.size() < 4) return false;
        static const DWORD magicNumbers[] = {
            0x00000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000,
            0x00000001, 0xFFFFFFFE
        };
        size_t pos   = rand() % (data.size() - 3);
        DWORD  magic = magicNumbers[rand() % 6];
        memcpy(&data[pos], &magic, sizeof(DWORD));
        return true;
    }
    string getName() const { return "MagicNumber"; }
};

class PdfStructureMutator : public Mutator {
public:
    bool mutate(vector<unsigned char>& data) {
        if (data.size() < 10) return false;
        string s(data.begin(), data.end());
        static const char* targets[] = {
            "xref", "trailer", "startxref", "stream", "endstream",
            "obj", "endobj", "/Type", "/Page", "/Length",
            "/Filter", "/Root", "/Pages", "/Kids", "/Count",
            "%%EOF", "/XObject", "/Font", "/Encrypt", "/JavaScript"
        };
        static const int numTargets = 20;
        const char* keyword = targets[rand() % numTargets];
        size_t kwLen        = strlen(keyword);
        vector<size_t> positions;
        size_t pos = 0;
        while ((pos = s.find(keyword, pos)) != string::npos) {
            positions.push_back(pos);
            pos += kwLen;
        }
        if (positions.empty()) {
            size_t insertAt = rand() % data.size();
            string garbage  = "/FakeKey_" + string(1, (char)('A' + rand() % 26));
            data.insert(data.begin() + insertAt, garbage.begin(), garbage.end());
            return true;
        }
        size_t target = positions[rand() % positions.size()];
        int action    = rand() % 4;
        if (action == 0) {
            size_t byteToFlip = target + (rand() % kwLen);
            if (byteToFlip < data.size())
                data[byteToFlip] ^= (unsigned char)(rand() % 256);
        } else if (action == 1) {
            size_t insertAt = target + kwLen;
            if (insertAt <= data.size()) {
                size_t count = 1 + rand() % 8;
                for (size_t i = 0; i < count; i++)
                    data.insert(data.begin() + insertAt, (unsigned char)(rand() % 256));
            }
        } else if (action == 2) {
            size_t end = min(target + kwLen, data.size());
            data.erase(data.begin() + target, data.begin() + end);
        } else {
            size_t end         = min(target + kwLen, data.size());
            string replacement = to_string((size_t)rand() * rand());
            data.erase(data.begin() + target, data.begin() + end);
            if (target <= data.size())
                data.insert(data.begin() + target, replacement.begin(), replacement.end());
        }
        return true;
    }
    string getName() const { return "PdfStructure"; }
};

// NOTE: PdfJavaScriptInjector and EncryptInjector are kept for paper documentation
// but are NOT registered as active mutators. They inject /OpenAction entries that
// make SumatraPDF pop dialogs and hang — causing 100% timeouts against a GUI target.

class PdfJavaScriptInjector : public Mutator {
public:
    bool mutate(vector<unsigned char>& data) {
        if (data.size() < 10) return false;
        string s(data.begin(), data.end());
        static const char* payloads[] = {
            "\n10 0 obj\n<</Type /Action /S /JavaScript /JS (app.alert('fuzz');)>>\nendobj\n"
            "11 0 obj\n<</OpenAction 10 0 R>>\nendobj\n",
            "\n40 0 obj\n<</Type /Action /S /Launch /Win <</F (cmd.exe) /P (/c whoami)>>>>\nendobj\n"
            "41 0 obj\n<</OpenAction 40 0 R>>\nendobj\n",
        };
        string payloadStr(payloads[rand() % 2]);
        size_t eofPos   = s.rfind("%%EOF");
        size_t insertAt = (eofPos != string::npos) ? eofPos : data.size();
        if (data.size() + payloadStr.size() > 15 * 1024 * 1024) return false;
        data.insert(data.begin() + insertAt, payloadStr.begin(), payloadStr.end());
        return true;
    }
    string getName() const { return "JsInjector"; }
};

class EncryptInjector : public Mutator {
public:
    bool mutate(vector<unsigned char>& data) {
        if (data.size() < 10) return false;
        string s(data.begin(), data.end());
        static const char* encryptBlocks[] = {
            "\n90 0 obj\n<</Filter /Standard /V 2 /R 3 /Length 128 /P -3904 "
            "/O (AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA) "
            "/U (BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB)>>\nendobj\n",
        };
        string blockStr(encryptBlocks[0]);
        size_t eofPos   = s.rfind("%%EOF");
        size_t insertAt = (eofPos != string::npos) ? eofPos : data.size();
        if (data.size() + blockStr.size() > 15 * 1024 * 1024) return false;
        data.insert(data.begin() + insertAt, blockStr.begin(), blockStr.end());
        return true;
    }
    string getName() const { return "EncryptInjector"; }
};

// ================================================
// TARGET
// ================================================

class TargetFunction {
public:
    virtual FuzzResult execute(const vector<unsigned char>& input, CrashData& crashData) = 0;
    virtual ~TargetFunction() {}
};

class SumatraTarget : public TargetFunction {
private:
    string targetPath;
    unsigned int timeoutMs;
    size_t maxInputSize;

    string escapeCommandLineArg(const string& arg) {
        string escaped = "\"";
        for (size_t i = 0; i < arg.size(); i++) {
            char c = arg[i];
            if (c == '\"')      escaped += "\\\"";
            else if (c == '\\') escaped += "\\\\";
            else                escaped += c;
        }
        escaped += "\"";
        return escaped;
    }

    string getCrashType(DWORD exitCode) {
        switch (exitCode) {
            case 0xC0000005: return "ACCESS_VIOLATION";
            case 0xC000001D: return "ILLEGAL_INSTRUCTION";
            case 0xC0000094: return "INTEGER_DIVIDE_BY_ZERO";
            case 0xC00000FD: return "STACK_OVERFLOW";
            case 0xC000008E: return "FLOAT_DIVIDE_BY_ZERO";
            case 0xC000008C: return "ARRAY_BOUNDS_EXCEEDED";
            case 0xC0000409: return "STACK_BUFFER_OVERRUN";
            case 0xC0000374: return "HEAP_CORRUPTION";
            case 0xC0000417: return "INVALID_CRUNTIME_PARAMETER";
            case 0x80000003: return "BREAKPOINT";
            case 0x80000004: return "SINGLE_STEP";
            case 1:          return "LOAD_ERROR";
            default: {
                stringstream ss;
                ss << "EXCEPTION_0x" << hex << uppercase << exitCode;
                return ss.str();
            }
        }
    }

    CrashSeverity getSeverity(DWORD exitCode) {
        switch (exitCode) {
            case 0xC0000005: case 0xC000001D: case 0xC0000094:
            case 0xC00000FD: case 0xC000008E: case 0xC000008C:
            case 0xC0000409: case 0xC0000374: case 0xC0000417:
            case 0xC0000025: case 0xC0000602:
                return SEV_REAL_CRASH;
            case 0x80000003: case 0x80000004:
                return SEV_EXCEPTION;
            case 1:
                return SEV_LOAD_ERROR;
            case 0xC000026B: case 0xC0000135: case 0xC0000142:
            case 0xC000007B: case 0xC000003A: case 0xC0000034:
            case 0xC0000022: case 0x40000015:
                return SEV_ABNORMAL;
            default:
                if (exitCode >= 0xC0000000 && exitCode <= 0xCFFFFFFF) return SEV_REAL_CRASH;
                if (exitCode >= 0x80000000) return SEV_EXCEPTION;
                return SEV_ABNORMAL;
        }
    }

    bool analyzeForMaliciousContent(const vector<unsigned char>& data,
                                     vector<string>& foundKeys) {
        if (data.size() < 10) return false;
        string s(data.begin(), data.end());
        static const struct { const char* keyword; const char* description; } suspects[] = {
            { "/JavaScript",   "/JavaScript"   },
            { "/JS ",          "/JS (short)"   },
            { "/JS\n",         "/JS (newline)" },
            { "/OpenAction",   "/OpenAction"   },
            { "/AA ",          "/AA (actions)" },
            { "/Launch",       "/Launch"       },
            { "/URI",          "/URI"          },
            { "/SubmitForm",   "/SubmitForm"   },
            { "/ImportData",   "/ImportData"   },
            { "/RichMedia",    "/RichMedia"    },
            { "/XFA",          "/XFA"          },
            { "/Encrypt",      "/Encrypt"      },
            { "/EmbeddedFile", "/EmbeddedFile" },
            { "/JBIG2Decode",  "/JBIG2Decode"  },
            { "/GoToR",        "/GoToR"        },
            { "/GoToE",        "/GoToE"        },
        };
        static const int numSuspects = 16;
        foundKeys.clear();
        for (int i = 0; i < numSuspects; i++)
            if (s.find(suspects[i].keyword) != string::npos)
                foundKeys.push_back(suspects[i].description);
        return foundKeys.size() >= 1;
    }

public:
    SumatraTarget(const string& path, unsigned int timeout, size_t maxSize)
        : targetPath(path), timeoutMs(timeout), maxInputSize(maxSize)
    {
        if (!FileManager::exists(targetPath))
            cerr << "[WARNING] Target not found: " << targetPath << endl;
        else
            cout << "[INFO] Target found: " << targetPath << endl;
    }

    FuzzResult execute(const vector<unsigned char>& input, CrashData& crashData) {
        if (input.empty() || input.size() > maxInputSize)
            return INVALID_INPUT;

        vector<string> foundKeys;
        bool malicious = analyzeForMaliciousContent(input, foundKeys);
        crashData.isMalicious   = malicious;
        crashData.maliciousKeys = foundKeys;

        string tempFile = FileManager::generateTempFilename(".pdf");
        if (!FileManager::writeFile(tempFile, input)) {
            cerr << "[ERROR] Couldn't write temp PDF: " << tempFile << endl;
            return HARNESS_ERROR;
        }

        // ── KEY FIX: Kill any leftover SumatraPDF before each iteration ──────
        // SumatraPDF is a single-instance app. If one is already running,
        // a new file just opens as a tab in that window instead of launching
        // a fresh process — that window never calls -exit-when-done and hangs.
        // taskkill /F = force, /IM = by image name, >nul 2>&1 = suppress output
        system("taskkill /F /IM sumatrapdf.exe >nul 2>&1");
        Sleep(300);

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb          = sizeof(si);
        // SW_SHOWMINNOACTIVE: window created minimized but Win32 message loop
        // runs normally so -exit-when-done fires. SW_HIDE blocks the message loop.
        si.dwFlags     = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOWMINNOACTIVE;
        ZeroMemory(&pi, sizeof(pi));

        string cmdLine = escapeCommandLineArg(targetPath)
                       + " -exit-when-done "
                       + escapeCommandLineArg(tempFile);
        vector<char> cmdBuf(cmdLine.begin(), cmdLine.end());
        cmdBuf.push_back('\0');

        // Creation flags = 0, NOT CREATE_NO_WINDOW.
        // CREATE_NO_WINDOW blocks the GUI message loop → -exit-when-done never fires.
        if (!CreateProcessA(NULL, &cmdBuf[0], NULL, NULL, FALSE,
                            0, NULL, NULL, &si, &pi)) {
            DWORD err = GetLastError();
            cerr << "[ERROR] CreateProcess failed (error " << err << ")" << endl;
            FileManager::removeFile(tempFile);
            return HARNESS_ERROR;
        }

        DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
        FuzzResult result = NORMAL;
        DWORD exitCode    = 0;

        if (waitResult == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 9);
            WaitForSingleObject(pi.hProcess, 1000);
            result               = TIMEOUT;
            crashData.crashType  = "TIMEOUT";
            crashData.severity   = SEV_TIMEOUT;
            crashData.exitCode   = 9;
            crashData.timestamp  = time(NULL);
            crashData.filename   = tempFile;
            crashData.triggeringInput = input;
            cout << "[TIMEOUT]    iter " << crashData.iterationNumber
                 << (malicious ? " [MALICIOUS]" : "") << endl;
        }
        else if (waitResult == WAIT_OBJECT_0) {
            GetExitCodeProcess(pi.hProcess, &exitCode);
            crashData.exitCode        = exitCode;
            crashData.timestamp       = time(NULL);
            crashData.filename        = tempFile;
            crashData.triggeringInput = input;
            crashData.crashType       = getCrashType(exitCode);
            CrashSeverity sev         = getSeverity(exitCode);
            crashData.severity        = sev;
            if (malicious) crashData.crashType += "_MALICIOUS";

            if (exitCode == 0) {
                cout << "[OK]         iter " << crashData.iterationNumber
                     << (malicious ? " [malicious structures, opened OK]" : "") << endl;
                result = NORMAL;
            }
            else if (sev == SEV_REAL_CRASH || sev == SEV_EXCEPTION) {
                result = CRASH_DETECTED;
                cout << "[CRASH-MEM]  iter " << crashData.iterationNumber
                     << " | " << crashData.crashType
                     << " | exit=0x" << hex << uppercase << exitCode << dec
                     << (malicious ? " [MALICIOUS]" : "") << endl;
            }
            else if (sev == SEV_LOAD_ERROR) {
                // Exit code 1 = SumatraPDF showed "Error loading" banner = crash
                result = LOAD_ERROR_DETECTED;
                cout << "[CRASH-LOAD] iter " << crashData.iterationNumber
                     << " | SumatraPDF failed to load PDF (exit=1)"
                     << (malicious ? " [MALICIOUS]" : "") << endl;
            }
            else {
                // SEV_ABNORMAL: process startup failure, not a PDF parser event
                result = NORMAL;
            }
        }
        else {
            result = HARNESS_ERROR;
            cerr << "[ERROR] Unexpected WaitForSingleObject result" << endl;
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        FileManager::removeFile(tempFile);

        return result;
    }
};

// ================================================
// HARNESS
// ================================================

class Harness {
private:
    TargetFunction* target;
    CrashLogger* logger;
    vector<Mutator*> mutators;
    Config config;
    size_t iterationCount;
    size_t totalCrashes;
    size_t totalLoadErrors;
    size_t totalMaliciousDetected;
    size_t totalTimeouts;
    size_t totalErrors;
    StatsManager* statsManager;

    string toString(size_t val) { stringstream ss; ss << val; return ss.str(); }
    string toStringDouble(double val) { stringstream ss; ss << fixed << setprecision(2) << val; return ss.str(); }

public:
    Harness(TargetFunction* t, CrashLogger* l, const Config& cfg)
        : target(t), logger(l), config(cfg),
          iterationCount(0), totalCrashes(0), totalLoadErrors(0),
          totalMaliciousDetected(0), totalTimeouts(0), totalErrors(0),
          statsManager(nullptr) {}

    ~Harness() {
        for (size_t i = 0; i < mutators.size(); i++) delete mutators[i];
        delete target;
    }

    void setStatsManager(StatsManager* stats) { statsManager = stats; }
    void addMutator(Mutator* m) { mutators.push_back(m); }

    void runFuzzingSession(size_t maxIterations) {
        // Kill any SumatraPDF open from before we started
        cout << "[*] Killing any open SumatraPDF instances..." << endl;
        system("taskkill /F /IM sumatrapdf.exe >nul 2>&1");
        Sleep(500);
        cout << "[*] Ready. Starting fuzzing." << endl << endl;

        logger->logInfo("=== Starting fuzzing session ===");
        logger->logInfo("Target: " + config.executablePath);
        logger->logInfo("Timeout: " + toString(config.timeoutMs) + "ms");
        logger->logInfo("Max iterations: " + toString(maxIterations));

        if (!FileManager::exists(config.executablePath)) {
            logger->logError("Target executable not found: " + config.executablePath);
            return;
        }
        if (!FileManager::exists(config.seedDirectory)) {
            logger->logError("Seed directory not found: " + config.seedDirectory);
            return;
        }

        vector<string> seedFiles = FileManager::getFilesInDirectory(config.seedDirectory);
        if (seedFiles.empty()) { logger->logError("No seed files in: " + config.seedDirectory); return; }
        if (mutators.empty())  { logger->logError("No mutators registered."); return; }

        logger->logInfo("Found " + toString(seedFiles.size()) + " files in seed dir");
        logger->logInfo("Registered " + toString(mutators.size()) + " mutators");

        vector<vector<unsigned char>> seeds;
        vector<string> validSeedFiles;

        for (size_t i = 0; i < seedFiles.size(); i++) {
            const string& f = seedFiles[i];
            string ext;
            size_t dotPos = f.find_last_of('.');
            if (dotPos != string::npos) {
                ext = f.substr(dotPos);
                for (size_t c = 0; c < ext.size(); c++) ext[c] = (char)tolower((unsigned char)ext[c]);
            }
            if (ext != ".pdf") continue;

            vector<unsigned char> seed;
            if (!FileManager::readFile(f, seed) || seed.empty() || seed.size() > config.maxInputSize) {
                logger->logInfo("Could not read or too large: " + f);
                continue;
            }
            if (seed.size() < 4 || seed[0]!='%' || seed[1]!='P' || seed[2]!='D' || seed[3]!='F') {
                logger->logInfo("Not a valid PDF (bad magic): " + f);
                continue;
            }
            seeds.push_back(seed);
            validSeedFiles.push_back(f);
        }

        if (seeds.empty()) { logger->logError("No valid PDF seeds loaded."); return; }

        logger->logInfo("Loaded " + toString(seeds.size()) + " valid PDF seeds");
        logger->logInfo("Starting fuzzing loop...");

        time_t startTime = time(NULL);

        for (size_t i = 0; i < maxIterations; i++) {
            size_t idx = rand() % seeds.size();
            vector<unsigned char> input = seeds[idx];

            string mutatorUsed;
            if (rand() % 5 == 0) {
                Mutator* m = mutators[rand() % mutators.size()];
                m->mutate(input);
                mutatorUsed = m->getName();
            } else {
                size_t mutationCount = 5 + (rand() % 10);
                for (size_t m = 0; m < mutationCount; m++) {
                    Mutator* mut = mutators[rand() % mutators.size()];
                    mut->mutate(input);
                    if (!mutatorUsed.empty()) mutatorUsed += "+";
                    mutatorUsed += mut->getName();
                }
            }

            // Always restore PDF header after mutation
            if (input.size() >= 4) { input[0]='%'; input[1]='P'; input[2]='D'; input[3]='F'; }

            CrashData crash;
            crash.seedFilename    = validSeedFiles[idx];
            crash.iterationNumber = i;
            crash.triggeringInput = input;
            crash.mutatorUsed     = mutatorUsed;

            FuzzResult result = target->execute(input, crash);

            if (result == CRASH_DETECTED) {
                totalCrashes++;
                if (crash.isMalicious) totalMaliciousDetected++;
                logger->logCrash(crash);
            }
            else if (result == LOAD_ERROR_DETECTED) {
                totalLoadErrors++;
                if (crash.isMalicious) totalMaliciousDetected++;
                logger->logLoadError(crash);
            }
            else if (result == TIMEOUT) {
                totalTimeouts++;
                if (crash.isMalicious) totalMaliciousDetected++;
            }
            else if (result == HARNESS_ERROR) {
                totalErrors++;
            }

            iterationCount++;

            if (i > 0 && i % 100 == 0) {
                time_t elapsed = time(NULL) - startTime;
                double rate    = static_cast<double>(i) / (elapsed > 0 ? elapsed : 1);
                stringstream ss;
                ss << "Progress: " << i << "/" << maxIterations
                   << " (" << fixed << setprecision(1) << (i * 100.0 / maxIterations) << "%)"
                   << "  Rate: "       << fixed << setprecision(2) << rate << " exec/s"
                   << "  Crashes: "    << totalCrashes
                   << "  LoadErrors: " << totalLoadErrors
                   << "  Timeouts: "   << totalTimeouts
                   << "  Malicious: "  << totalMaliciousDetected;
                logger->logInfo(ss.str());
                logger->flush();
            }
        }

        time_t totalTime = time(NULL) - startTime;
        double avgRate   = static_cast<double>(iterationCount) / (totalTime > 0 ? totalTime : 1);

        FuzzingStats stats;
        stats.totalIterations = iterationCount;
        stats.totalCrashes    = totalCrashes;
        stats.totalLoadErrors = totalLoadErrors;
        stats.totalMalicious  = totalMaliciousDetected;
        stats.totalTimeouts   = totalTimeouts;
        stats.totalErrors     = totalErrors;
        stats.startTime       = startTime;
        stats.endTime         = time(NULL);
        stats.executionRate   = avgRate;

        if (statsManager) statsManager->saveSessionStats(stats);

        logger->logInfo("=== Fuzzing session complete ===");
        logger->logInfo("Total iterations : " + toString(iterationCount));
        logger->logInfo("Real crashes     : " + toString(totalCrashes));
        logger->logInfo("Load errors      : " + toString(totalLoadErrors));
        logger->logInfo("Malicious inputs : " + toString(totalMaliciousDetected));
        logger->logInfo("Timeouts         : " + toString(totalTimeouts));
        logger->logInfo("Total time       : " + toString(totalTime) + "s");
        logger->logInfo("Avg exec rate    : " + toStringDouble(avgRate) + " exec/s");

        if (statsManager) statsManager->printRecentCrashes(5);
        logger->flush();
    }
};

// ================================================
// MAIN
// ================================================

int main(int argc, char* argv[]) {
    srand(static_cast<unsigned>(time(NULL)));

    Config config;

    if (argc > 1) {
        config.executablePath = argv[1];
        cout << "[INFO] Using custom executable path: " << config.executablePath << endl;
    }

    if (!FileManager::exists(config.executablePath)) {
        cerr << "[ERROR] Target executable not found: " << config.executablePath << endl;
        return 1;
    }

    DatabaseManager* dbManager = new DatabaseManager();
    if (!dbManager->initialize(config.databaseFile)) {
        cerr << "[ERROR] Database initialization failed!" << endl;
        delete dbManager;
        return 1;
    }

    StatsManager* statsManager = new StatsManager(config.statsFile);
    statsManager->setDatabaseManager(dbManager);
    statsManager->initialize();

    CrashLogger* crashLogger = new CrashLogger();
    if (!crashLogger->initialize(config))
        cerr << "[WARNING] Logger initialization failed" << endl;
    crashLogger->setStatsManager(statsManager);

    SumatraTarget* sumatraTarget = new SumatraTarget(
        config.executablePath, config.timeoutMs, config.maxInputSize
    );

    Harness harness(sumatraTarget, crashLogger, config);
    harness.setStatsManager(statsManager);

    // ── Active mutators ───────────────────────────────────────────────────────
    // PdfJavaScriptInjector and EncryptInjector are intentionally NOT registered.
    // They inject /OpenAction entries that make SumatraPDF pop dialogs and hang,
    // causing 100% timeouts when black-box fuzzing a GUI application.
    harness.addMutator(new BitFlipMutator());
    harness.addMutator(new ByteFlipMutator());
    harness.addMutator(new InsertBytesMutator());
    harness.addMutator(new DeleteBytesMutator());
    harness.addMutator(new MagicNumberMutator());
    harness.addMutator(new PdfStructureMutator());

    size_t iterations = 10000;
    if (argc > 2) iterations = static_cast<size_t>(atoi(argv[2]));

    cout << "\n[INFO] Starting fuzzing — " << iterations << " iterations" << endl;
    cout << "[INFO] Target:   " << config.executablePath << endl;
    cout << "[INFO] Seeds:    " << config.seedDirectory  << endl;
    cout << "[INFO] Output:   " << config.outputDirectory << endl;
    cout << "[INFO] Database: " << config.databaseFile   << endl;
    cout << "============================================\n" << endl;

    harness.runFuzzingSession(iterations);

    int totalCrashes = dbManager->getTotalCrashes();
    int maliciousHit = dbManager->getTotalMalicious();

    cout << "\n[INFO] ===== FINAL DATABASE SUMMARY =====" << endl;
    cout << "  Total crashes saved:       " << totalCrashes << endl;
    cout << "  Inputs with malicious PDF: " << maliciousHit << endl;
    cout << "  Database:                  " << config.databaseFile << endl;
    cout << "\nOutput files:" << endl;
    cout << "  Log:     " << config.logFile       << endl;
    cout << "  Stats:   " << config.statsFile     << endl;
    cout << "  Crashes: " << config.crashDirectory << endl;
    cout << "  DB:      " << config.databaseFile  << endl;

    delete crashLogger;
    delete statsManager;
    delete dbManager;

    return 0;
}