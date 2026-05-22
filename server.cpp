#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <sqlite3.h>
#include <direct.h>
#include <process.h>
#include <iomanip>
#include <chrono>
#include <map>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

// ================================================
// CONFIGURATION
// ================================================

struct Config {
    int port = 8080;
    string webRoot = ".";
    string fuzzerPath = "fuzzer.exe";
    string sumatraPath = "SumatraPDF.exe";
    string databasePath = "outputs/fuzzing.db";
    string uploadDir = "inputs/seeds";   // FIX: upload directly into seeds folder so fuzzer picks them up
};

// ================================================
// DATABASE MANAGER
// ================================================

class DatabaseManager {
private:
    sqlite3* db;
    string dbPath;
    bool connected;

public:
    DatabaseManager(const string& path) : db(nullptr), dbPath(path), connected(false) {}

    ~DatabaseManager() {
        if (db) sqlite3_close(db);
    }

    bool connect() {
        int rc = sqlite3_open(dbPath.c_str(), &db);
        if (rc) {
            cerr << "[SERVER] Can't open database: " << sqlite3_errmsg(db) << endl;
            connected = false;
            return false;
        }
        connected = true;
        cout << "[SERVER] Database connected: " << dbPath << endl;
        return true;
    }

    bool isConnected() const { return connected && db != nullptr; }

    string getCrashesJSON() {
        if (!db) return "[]";

        sqlite3_stmt* stmt;
        // FIX: added severity and is_malicious columns that exist in the fuzzer schema
        const char* sql =
            "SELECT id, human_time, iteration, crash_type, severity, exit_code, "
            "       filename, input_size, mutator_used, is_malicious "
            "FROM crashes ORDER BY id DESC LIMIT 50";

        stringstream json;
        json << "[";

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            bool first = true;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                if (!first) json << ",";
                first = false;

                // Safe JSON string escaping
                auto safeStr = [&](int col) -> string {
                    const unsigned char* t = sqlite3_column_text(stmt, col);
                    if (!t) return "";
                    string s((const char*)t);
                    string out;
                    for (char c : s) {
                        if      (c == '"')  out += "\\\"";
                        else if (c == '\\') out += "\\\\";
                        else if (c == '\n') out += "\\n";
                        else if (c == '\r') out += "\\r";
                        else                out += c;
                    }
                    return out;
                };

                json << "{";
                json << "\"id\":"             << sqlite3_column_int(stmt, 0)    << ",";
                json << "\"timestamp\":\""    << safeStr(1)                     << "\",";
                json << "\"iteration\":"      << sqlite3_column_int(stmt, 2)    << ",";
                json << "\"crash_type\":\""   << safeStr(3)                     << "\",";
                json << "\"severity\":\""     << safeStr(4)                     << "\",";
                json << "\"exit_code\":"      << sqlite3_column_int(stmt, 5)    << ",";
                json << "\"filename\":\""     << safeStr(6)                     << "\",";
                json << "\"input_size\":"     << sqlite3_column_int(stmt, 7)    << ",";
                json << "\"mutator_used\":\"" << safeStr(8)                     << "\",";
                json << "\"is_malicious\":"   << sqlite3_column_int(stmt, 9);
                json << "}";
            }
            sqlite3_finalize(stmt);
        }

        json << "]";
        return json.str();
    }

    string getStatsJSON() {
        if (!db) return "{}";

        stringstream json;
        json << "{";

        sqlite3_stmt* stmt;

        // FIX: count only real security crashes matching fuzzer logic
        const char* sql1 = "SELECT COUNT(*) FROM crashes WHERE severity IN ('REAL_CRASH','EXCEPTION')";
        if (sqlite3_prepare_v2(db, sql1, -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW)
                json << "\"total_crashes\":" << sqlite3_column_int(stmt, 0) << ",";
            sqlite3_finalize(stmt);
        }

        const char* sql_le = "SELECT COUNT(*) FROM crashes WHERE severity='LOAD_ERROR'";
        if (sqlite3_prepare_v2(db, sql_le, -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW)
                json << "\"total_load_errors\":" << sqlite3_column_int(stmt, 0) << ",";
            sqlite3_finalize(stmt);
        }

        const char* sql_mal = "SELECT COUNT(*) FROM crashes WHERE is_malicious=1";
        if (sqlite3_prepare_v2(db, sql_mal, -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW)
                json << "\"total_malicious\":" << sqlite3_column_int(stmt, 0) << ",";
            sqlite3_finalize(stmt);
        }

        // FIX: select columns by name — not positional index — to survive schema order changes
        // Schema: id, start_time, end_time, total_iterations, total_crashes,
        //         total_load_errors, total_malicious, total_timeouts, total_errors,
        //         execution_rate, human_start_time, human_end_time
        const char* sql2 =
            "SELECT total_iterations, total_crashes, total_load_errors, "
            "       total_malicious, total_timeouts, execution_rate "
            "FROM sessions ORDER BY id DESC LIMIT 1";
        if (sqlite3_prepare_v2(db, sql2, -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                json << "\"last_iterations\":"  << sqlite3_column_int(stmt, 0)    << ",";
                json << "\"last_crashes\":"     << sqlite3_column_int(stmt, 1)    << ",";
                json << "\"last_load_errors\":" << sqlite3_column_int(stmt, 2)    << ",";
                json << "\"last_malicious\":"   << sqlite3_column_int(stmt, 3)    << ",";
                json << "\"last_timeouts\":"    << sqlite3_column_int(stmt, 4)    << ",";
                json << "\"last_rate\":"        << sqlite3_column_double(stmt, 5);
            } else {
                json << "\"last_iterations\":0,\"last_crashes\":0,\"last_load_errors\":0,"
                        "\"last_malicious\":0,\"last_timeouts\":0,\"last_rate\":0";
            }
            sqlite3_finalize(stmt);
        }

        json << "}";
        return json.str();
    }

    string getConsoleData() {
        if (!db) return "Database not connected";

        stringstream console;
        console << "+----------------------------------------------+\n";
        console << "           FUZZING DATABASE CONSOLE             \n";
        console << "+----------------------------------------------+\n\n";

        // Recent crashes
        console << ">> RECENT CRASHES (Last 10):\n";
        console << left
                << setw(6)  << "ID"
                << setw(22) << "Timestamp"
                << setw(10) << "Iter"
                << setw(20) << "Crash Type"
                << setw(14) << "Severity"
                << setw(10) << "Malicious"
                << "\n"
                << string(82, '-') << "\n";

        sqlite3_stmt* stmt;
        const char* q1 =
            "SELECT id, human_time, iteration, crash_type, severity, is_malicious "
            "FROM crashes ORDER BY id DESC LIMIT 10";

        if (sqlite3_prepare_v2(db, q1, -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int         id   = sqlite3_column_int(stmt, 0);
                const char* ts   = (const char*)sqlite3_column_text(stmt, 1);
                int         iter = sqlite3_column_int(stmt, 2);
                const char* ct   = (const char*)sqlite3_column_text(stmt, 3);
                const char* sev  = (const char*)sqlite3_column_text(stmt, 4);
                int         mal  = sqlite3_column_int(stmt, 5);

                string crashType(ct  ? ct  : "");
                string severity (sev ? sev : "");
                if (crashType.size() > 18) crashType = crashType.substr(0, 17) + "..";
                if (severity.size()  > 12) severity  = severity.substr(0,  11) + "..";

                console << left
                        << setw(6)  << id
                        << setw(22) << (ts ? ts : "N/A")
                        << setw(10) << iter
                        << setw(20) << crashType
                        << setw(14) << severity
                        << setw(10) << (mal ? "YES ***" : "no")
                        << "\n";
            }
            sqlite3_finalize(stmt);
        }
        console << string(82, '-') << "\n\n";

        // Aggregate statistics
        console << ">> STATISTICS:\n" << string(44, '-') << "\n";
        const char* q2 =
            "SELECT "
            "  SUM(CASE WHEN severity IN ('REAL_CRASH','EXCEPTION') THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN severity='LOAD_ERROR' THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN is_malicious=1 THEN 1 ELSE 0 END), "
            "  MAX(iteration), "
            "  COUNT(DISTINCT crash_type) "
            "FROM crashes";

        if (sqlite3_prepare_v2(db, q2, -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                console << "  Real Crashes:    " << setw(8) << sqlite3_column_int(stmt, 0) << "\n";
                console << "  Load Errors:     " << setw(8) << sqlite3_column_int(stmt, 1) << "\n";
                console << "  Malicious:       " << setw(8) << sqlite3_column_int(stmt, 2) << "\n";
                console << "  Last Iteration:  " << setw(8) << sqlite3_column_int(stmt, 3) << "\n";
                console << "  Unique Types:    " << setw(8) << sqlite3_column_int(stmt, 4) << "\n";
            }
            sqlite3_finalize(stmt);
        }

        // Recent sessions — FIX: select by column name, not positional index
        console << "\n>> RECENT SESSIONS:\n" << string(44, '-') << "\n";
        const char* q3 =
            "SELECT id, human_start_time, total_iterations, total_crashes, "
            "       total_load_errors, total_malicious, execution_rate "
            "FROM sessions ORDER BY id DESC LIMIT 5";

        if (sqlite3_prepare_v2(db, q3, -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int         sid  = sqlite3_column_int(stmt, 0);
                const char* st   = (const char*)sqlite3_column_text(stmt, 1);
                int         itr  = sqlite3_column_int(stmt, 2);
                int         crs  = sqlite3_column_int(stmt, 3);
                int         le   = sqlite3_column_int(stmt, 4);
                int         mal  = sqlite3_column_int(stmt, 5);
                double      rate = sqlite3_column_double(stmt, 6);

                console << "Session " << sid << " [" << (st ? st : "?") << "]: "
                        << itr  << " iters | "
                        << crs  << " crashes | "
                        << le   << " load_errors | "
                        << mal  << " malicious | "
                        << fixed << setprecision(2) << rate << " exec/s\n";
            }
            sqlite3_finalize(stmt);
        }

        console << "\nLast updated: " << getCurrentTimestamp() << "\n";
        return console.str();
    }

private:
    string getCurrentTimestamp() {
        time_t t = time(nullptr);
        char buf[64];
        struct tm* ti = localtime(&t);   // MinGW/g++ compatible
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", ti);
        return string(buf);
    }
};

// ================================================
// FILE UPLOAD MANAGER
// ================================================

class FileUploadManager {
private:
    string uploadDir;

public:
    FileUploadManager(const string& dir) : uploadDir(dir) {}

    bool createUploadDir() {
        return _mkdir(uploadDir.c_str()) == 0 || errno == EEXIST;
    }

    // FIX: preserve original filename so fuzzer recognises .pdf seeds
    string saveUploadedFile(const vector<char>& data,
                            const string& originalName,
                            int index) {
        string filename = originalName;
        if (filename.empty()) {
            filename = "uploaded_" + to_string(time(nullptr))
                     + "_" + to_string(index) + ".bin";
        } else {
            string safe;
            for (char c : filename) {
                if (isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-')
                    safe += c;
                else
                    safe += '_';
            }
            if (safe.empty()) safe = "file_" + to_string(index);
            filename = safe;
        }

        string filePath = uploadDir + "/" + filename;
        ofstream file(filePath, ios::binary);
        if (!file) return "";
        file.write(data.data(), data.size());
        file.close();
        return filePath;
    }
};

// ================================================
// HTTP REQUEST PARSER  (multipart/form-data)
// ================================================

struct MultipartField {
    string fieldName;
    string fileName;
    string data;
};

class HttpRequestParser {
public:
    // FIX: headersStart offset corrected — boundary line is "--<boundary>\r\n"
    //      so we skip: delim.size() (= 2 + boundary.size()) + 2 (for \r\n)
    // FIX: also parses filename= from Content-Disposition
    static vector<MultipartField> parseMultipart(const string& body,
                                                  const string& boundary) {
        vector<MultipartField> fields;
        const string delim = "--" + boundary;
        size_t pos = 0;

        while (true) {
            size_t bStart = body.find(delim, pos);
            if (bStart == string::npos) break;

            // Closing boundary "--boundary--"
            size_t afterDelim = bStart + delim.size();
            if (afterDelim + 2 <= body.size() &&
                body[afterDelim] == '-' && body[afterDelim + 1] == '-') break;

            // Skip "--boundary\r\n"  (FIX: +2 for \r\n)
            size_t headersStart = bStart + delim.size() + 2;
            size_t headersEnd   = body.find("\r\n\r\n", headersStart);
            if (headersEnd == string::npos) break;

            string headers = body.substr(headersStart, headersEnd - headersStart);

            size_t dataStart = headersEnd + 4;
            size_t nextBound = body.find("\r\n" + delim, dataStart);
            if (nextBound == string::npos) break;

            string data = body.substr(dataStart, nextBound - dataStart);

            MultipartField field;
            size_t cdPos = headers.find("Content-Disposition:");
            if (cdPos != string::npos) {
                size_t cdEnd = headers.find("\r\n", cdPos);
                string cd = headers.substr(cdPos, cdEnd == string::npos ? string::npos : cdEnd - cdPos);

                size_t np = cd.find("name=\"");
                if (np != string::npos) {
                    np += 6;
                    size_t ne = cd.find("\"", np);
                    field.fieldName = cd.substr(np, ne - np);
                }

                size_t fp = cd.find("filename=\"");
                if (fp != string::npos) {
                    fp += 10;
                    size_t fe = cd.find("\"", fp);
                    field.fileName = cd.substr(fp, fe - fp);
                }
            }

            field.data = data;
            if (!field.fieldName.empty())
                fields.push_back(field);

            pos = nextBound + 2;
        }

        return fields;
    }
};

// ================================================
// FUZZER MANAGER
// ================================================

class FuzzerManager {
private:
    atomic<bool> running{false};
    PROCESS_INFORMATION pi;

public:
    FuzzerManager() { ZeroMemory(&pi, sizeof(pi)); }

    // FIX: accept sumatraPath from caller instead of always using config default
    bool startFuzzing(const string& sumatraPath, int iterations) {
        if (running) return false;

        string command = "fuzzer.exe \"" + sumatraPath + "\" " + to_string(iterations);

        STARTUPINFOA si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        // FIX: use 0 (default) NOT CREATE_NO_WINDOW — SumatraPDF is a GUI app,
        //      CREATE_NO_WINDOW blocks its Win32 message loop causing 100% timeouts.
        if (!CreateProcessA(NULL, (LPSTR)command.c_str(), NULL, NULL, FALSE,
                            0, NULL, NULL, &si, &pi)) {
            cerr << "[SERVER] CreateProcess failed: " << GetLastError() << endl;
            return false;
        }

        running = true;
        cout << "[SERVER] Fuzzer started with PID: " << pi.dwProcessId << endl;
        return true;
    }

    bool stopFuzzing() {
        if (!running) return false;

        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        ZeroMemory(&pi, sizeof(pi));

        running = false;
        cout << "[SERVER] Fuzzer stopped" << endl;
        return true;
    }

    bool isRunning() {
        if (!running) return false;

        DWORD exitCode;
        if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
            if (exitCode != STILL_ACTIVE) {
                running = false;
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                ZeroMemory(&pi, sizeof(pi));
                return false;
            }
        }
        return true;
    }
};

// ================================================
// HTTP SERVER
// ================================================

class HttpServer {
private:
    SOCKET serverSocket = INVALID_SOCKET;
    Config config;
    DatabaseManager dbManager;
    FuzzerManager fuzzerManager;
    FileUploadManager uploadManager;

    string readFile(const string& path) {
        ifstream file(path, ios::binary);
        if (!file) return "";
        stringstream buf;
        buf << file.rdbuf();
        return buf.str();
    }

    string getMimeType(const string& path) {
        auto ends = [&](const string& ext) {
            return path.size() >= ext.size() &&
                   path.substr(path.size() - ext.size()) == ext;
        };
        if (ends(".html")) return "text/html";
        if (ends(".css"))  return "text/css";
        if (ends(".js"))   return "application/javascript";
        if (ends(".json")) return "application/json";
        return "text/plain";
    }

    void sendResponse(SOCKET client, const string& content,
                      const string& mime = "text/html", int code = 200) {
        string statusLine = (code == 200) ? "200 OK"
                          : (code == 404) ? "404 Not Found"
                                          : "400 Bad Request";
        stringstream resp;
        resp << "HTTP/1.1 " << statusLine    << "\r\n";
        resp << "Content-Type: "   << mime   << "\r\n";
        resp << "Content-Length: " << content.length() << "\r\n";
        resp << "Access-Control-Allow-Origin: *\r\n";
        resp << "Connection: close\r\n\r\n";
        resp << content;
        string s = resp.str();
        send(client, s.c_str(), (int)s.length(), 0);
    }

    void sendJSON(SOCKET client, const string& json) {
        sendResponse(client, json, "application/json");
    }

    // FIX: read the FULL request body — loops recv() until Content-Length is satisfied.
    //      The old single 8192-byte recv() truncated any file larger than ~8 KB.
    string readFullRequest(SOCKET client) {
        string request;
        char buf[16384];

        // Read until we have the full header block
        while (request.find("\r\n\r\n") == string::npos) {
            int n = recv(client, buf, sizeof(buf) - 1, 0);
            if (n <= 0) return request;
            request.append(buf, n);
        }

        // Parse Content-Length
        size_t headerEnd = request.find("\r\n\r\n");
        string headersOnly = request.substr(0, headerEnd);

        int contentLength = 0;
        // Case-insensitive search for Content-Length
        string headersLower = headersOnly;
        for (char& c : headersLower) c = (char)tolower((unsigned char)c);
        size_t clPos = headersLower.find("content-length:");
        if (clPos != string::npos) {
            size_t vs = headersOnly.find_first_not_of(" \t", clPos + 15);
            size_t ve = headersOnly.find("\r\n", vs);
            try { contentLength = stoi(headersOnly.substr(vs, ve - vs)); } catch (...) {}
        }

        int bodyReceived = (int)request.size() - (int)(headerEnd + 4);
        while (bodyReceived < contentLength) {
            int n = recv(client, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;
            request.append(buf, n);
            bodyReceived += n;
        }

        return request;
    }

    void handleFileUpload(SOCKET client, const string& body, const string& contentType) {
        cout << "[SERVER] File upload: " << body.size() << " bytes" << endl;

        size_t bPos = contentType.find("boundary=");
        if (bPos == string::npos) {
            sendJSON(client, "{\"success\":false,\"error\":\"No boundary in content type\"}");
            return;
        }
        string boundary = contentType.substr(bPos + 9);
        while (!boundary.empty() &&
               (boundary.back() == ' ' || boundary.back() == '\r' || boundary.back() == '\n'))
            boundary.pop_back();

        auto fields = HttpRequestParser::parseMultipart(body, boundary);

        int uploadedCount = 0;
        vector<string> uploadedFiles;

        for (auto& field : fields) {
            if (field.fieldName == "seedFiles" && !field.data.empty()) {
                string filePath = uploadManager.saveUploadedFile(
                    vector<char>(field.data.begin(), field.data.end()),
                    field.fileName,
                    uploadedCount
                );
                if (!filePath.empty()) {
                    uploadedCount++;
                    uploadedFiles.push_back(field.fileName.empty() ? filePath : field.fileName);
                    cout << "[SERVER] Saved: " << filePath
                         << " (" << field.data.size() << " bytes)" << endl;
                }
            }
        }

        if (uploadedCount > 0) {
            stringstream json;
            json << "{\"success\":true,\"uploaded\":" << uploadedCount << ",\"files\":[";
            for (size_t i = 0; i < uploadedFiles.size(); ++i) {
                if (i > 0) json << ",";
                json << "\"" << uploadedFiles[i] << "\"";
            }
            json << "]}";
            sendJSON(client, json.str());
        } else {
            sendJSON(client, "{\"success\":false,\"error\":\"No files were saved\"}");
        }
    }

    void handleApiRequest(SOCKET client, const string& method,
                          const string& path, const string& query,
                          const string& body, const string& contentType) {
        cout << "[SERVER] " << method << " " << path
             << (query.empty() ? "" : "?" + query) << endl;

        if (path == "/api/start") {
            // FIX: only POST can start fuzzing
            if (method != "POST") { sendJSON(client, "{\"error\":\"Method not allowed\"}"); return; }

            int iterations = 1000;
            size_t iterPos = query.find("iterations=");
            if (iterPos != string::npos) {
                try { iterations = stoi(query.substr(iterPos + 11)); } catch (...) {}
            }

            // FIX: read targetPath (SumatraPDF path) from query string
            string sumatraPath = config.sumatraPath;
            size_t targetPos = query.find("target=");
            if (targetPos != string::npos) {
                string raw = query.substr(targetPos + 7);
                // Stop at next '&' if present
                size_t amp = raw.find('&');
                if (amp != string::npos) raw = raw.substr(0, amp);
                // Minimal URL decode (%xx and +)
                string decoded;
                for (size_t i = 0; i < raw.size(); ) {
                    if (raw[i] == '%' && i + 2 < raw.size()) {
                        int val = 0;
                        for (int j = 1; j <= 2; j++) {
                            val <<= 4;
                            char c = raw[i + j];
                            if      (c >= '0' && c <= '9') val += c - '0';
                            else if (c >= 'a' && c <= 'f') val += c - 'a' + 10;
                            else if (c >= 'A' && c <= 'F') val += c - 'A' + 10;
                        }
                        decoded += (char)val;
                        i += 3;
                    } else if (raw[i] == '+') {
                        decoded += ' '; i++;
                    } else {
                        decoded += raw[i++];
                    }
                }
                if (!decoded.empty()) sumatraPath = decoded;
            }

            if (fuzzerManager.startFuzzing(sumatraPath, iterations)) {
                sendJSON(client, "{\"status\":\"started\",\"iterations\":"
                                 + to_string(iterations) + "}");
            } else {
                sendJSON(client, "{\"status\":\"error\",\"message\":\"Failed to start (already running?)\"}");
            }
        }
        else if (path == "/api/stop") {
            // FIX: only POST can stop — prevents accidental browser prefetch from killing the fuzzer
            if (method != "POST") { sendJSON(client, "{\"error\":\"Method not allowed\"}"); return; }
            if (fuzzerManager.stopFuzzing()) {
                sendJSON(client, "{\"status\":\"stopped\"}");
            } else {
                sendJSON(client, "{\"status\":\"error\",\"message\":\"Fuzzer not running\"}");
            }
        }
        else if (path == "/api/status") {
            bool isRunning = fuzzerManager.isRunning();
            // FIX: database_connected reflects real connection state (was hardcoded true)
            bool dbOk = dbManager.isConnected();
            stringstream json;
            json << "{";
            json << "\"running\":"            << (isRunning ? "true" : "false") << ",";
            json << "\"database_connected\":" << (dbOk      ? "true" : "false");
            json << "}";
            sendJSON(client, json.str());
        }
        else if (path == "/api/crashes") {
            sendJSON(client, dbManager.getCrashesJSON());
        }
        else if (path == "/api/stats") {
            sendJSON(client, dbManager.getStatsJSON());
        }
        else if (path == "/api/console") {
            string consoleData = dbManager.getConsoleData();
            stringstream json;
            json << "{\"data\":\"";
            for (char c : consoleData) {
                if      (c == '\n') json << "\\n";
                else if (c == '"')  json << "\\\"";
                else if (c == '\\') json << "\\\\";
                else if (c == '\r') ; // skip
                else                json << c;
            }
            json << "\"}";
            sendJSON(client, json.str());
        }
        else if (path == "/api/upload") {
            if (method != "POST" || body.empty()) {
                sendJSON(client, "{\"success\":false,\"error\":\"POST with body required\"}");
                return;
            }
            handleFileUpload(client, body, contentType);
        }
        else {
            sendJSON(client, "{\"error\":\"Unknown API endpoint\"}");
        }
    }

    void handleStaticFile(SOCKET client, const string& path) {
        string filePath = config.webRoot + path;
        if (filePath.back() == '/') filePath += "index.html";
        string content = readFile(filePath);
        if (!content.empty()) {
            sendResponse(client, content, getMimeType(filePath));
        } else {
            sendResponse(client, "<h1>404 Not Found</h1>", "text/html", 404);
        }
    }

public:
    HttpServer(const Config& cfg)
        : config(cfg), dbManager(cfg.databasePath), uploadManager(cfg.uploadDir) {}

    ~HttpServer() { stop(); }

    bool start() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            cerr << "[SERVER] Winsock init failed" << endl;
            return false;
        }

        serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSocket == INVALID_SOCKET) {
            cerr << "[SERVER] Socket creation failed" << endl;
            WSACleanup();
            return false;
        }

        // Allow port reuse so quick restarts don't fail with "address in use"
        int opt = 1;
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

        sockaddr_in addr;
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(config.port);

        if (bind(serverSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            cerr << "[SERVER] Bind failed: " << WSAGetLastError() << endl;
            closesocket(serverSocket); WSACleanup(); return false;
        }
        if (listen(serverSocket, 10) == SOCKET_ERROR) {
            cerr << "[SERVER] Listen failed" << endl;
            closesocket(serverSocket); WSACleanup(); return false;
        }

        uploadManager.createUploadDir();

        if (!dbManager.connect())
            cerr << "[SERVER] WARNING: DB not connected — stats will be empty" << endl;

        cout << "[SERVER] Running on http://localhost:" << config.port << endl;
        cout << "[SERVER] Web root:   " << config.webRoot      << endl;
        cout << "[SERVER] Upload dir: " << config.uploadDir    << endl;
        cout << "[SERVER] Database:   " << config.databasePath << endl;
        return true;
    }

    void run() {
        while (true) {
            SOCKET client = accept(serverSocket, NULL, NULL);
            if (client == INVALID_SOCKET) { cerr << "[SERVER] Accept failed" << endl; continue; }

            // FIX: read the full request including complete body before processing
            string request = readFullRequest(client);

            if (!request.empty()) {
                size_t methodEnd = request.find(' ');
                size_t pathEnd   = request.find(' ', methodEnd + 1);

                if (methodEnd != string::npos && pathEnd != string::npos) {
                    string method   = request.substr(0, methodEnd);
                    string fullPath = request.substr(methodEnd + 1, pathEnd - methodEnd - 1);

                    size_t queryStart = fullPath.find('?');
                    string path  = (queryStart != string::npos) ? fullPath.substr(0, queryStart) : fullPath;
                    string query = (queryStart != string::npos) ? fullPath.substr(queryStart + 1) : "";

                    string contentType, body;
                    size_t headerEnd = request.find("\r\n\r\n");
                    if (method == "POST" && headerEnd != string::npos) {
                        body = request.substr(headerEnd + 4);

                        // Find Content-Type header (case-insensitive)
                        string reqLower = request.substr(0, headerEnd);
                        for (char& c : reqLower) c = (char)tolower((unsigned char)c);
                        size_t ctPos = reqLower.find("content-type:");
                        if (ctPos != string::npos) {
                            size_t ctEnd = request.find("\r\n", ctPos);
                            contentType = request.substr(ctPos + 13,
                                ctEnd == string::npos ? string::npos : ctEnd - ctPos - 13);
                            size_t first = contentType.find_first_not_of(" \t");
                            if (first != string::npos) contentType = contentType.substr(first);
                        }
                    }

                    if (path.find("/api/") == 0) {
                        handleApiRequest(client, method, path, query, body, contentType);
                    } else {
                        handleStaticFile(client, path);
                    }
                }
            }

            closesocket(client);
        }
    }

    void stop() {
        fuzzerManager.stopFuzzing();
        if (serverSocket != INVALID_SOCKET) {
            closesocket(serverSocket);
            serverSocket = INVALID_SOCKET;
        }
        WSACleanup();
    }
};

// ================================================
// MAIN
// ================================================

int main() {
    cout << "============================================" << endl;
    cout << " FUZZER WEB SERVER  --  C++ Backend"         << endl;
    cout << "============================================" << endl;

    Config config;
    config.port         = 8080;
    config.webRoot      = ".";
    config.fuzzerPath   = "fuzzer.exe";
    config.sumatraPath  = "SumatraPDF.exe";
    config.databasePath = "outputs/fuzzing.db";
    config.uploadDir    = "inputs/seeds";

    HttpServer server(config);

    if (!server.start()) {
        cerr << "[SERVER] Failed to start" << endl;
        return 1;
    }

    cout << "[SERVER] Press Ctrl+C to stop" << endl;

    try {
        server.run();
    } catch (...) {
        server.stop();
    }

    return 0;
}