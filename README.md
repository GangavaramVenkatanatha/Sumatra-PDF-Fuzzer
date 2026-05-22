# 🔍 SumatraPDF Fuzzer

A coverage-guided **PDF fuzzer** targeting SumatraPDF, built entirely in C++.  
Includes a live web dashboard backed by a C++ HTTP server and SQLite database for real-time crash monitoring.

---

## 📸 Features

- **8 mutation strategies** — BitFlip, ByteFlip, InsertBytes, DeleteBytes, MagicNumber, PdfStructure, JavaScript Injector, Encrypt Injector
- **Severity classification** — distinguishes real memory-safety crashes (Access Violation, Stack Overflow, Heap Corruption) from parser rejections and OS-level failures
- **Malicious PDF detection** — content-based analysis flags dangerous PDF structures (`/JavaScript`, `/OpenAction`, `/Launch`, `/Encrypt`, `/XFA`, etc.)
- **SQLite persistence** — all crashes and session stats saved to `outputs/fuzzing.db`
- **Live web UI** — C++ HTTP server serves a real-time dashboard at `http://localhost:8080`
- **File upload** — drag-and-drop seed PDFs directly from the browser into the seeds folder
- **Console view** — live database console accessible from the UI

---

## 🗂️ Project Structure

```
.
├── fuzzer_final.cpp      # Core fuzzer — mutations, harness, crash detection
├── server.cpp            # C++ HTTP server — REST API + static file serving
├── index.html            # Web dashboard UI
├── sqlite3.dll           # SQLite3 runtime (Windows)
├── compile_server.bat    # Helper script to compile server
├── run_system.bat        # Helper script to start the server
├── inputs/
│   └── seeds/            # Seed PDF files go here (at least one required)
└── outputs/
    ├── fuzzing.db        # SQLite database (auto-created)
    ├── fuzzing.log       # Fuzzing log file
    ├── fuzzing_stats.txt # Session statistics
    └── crashes/          # Crash-triggering PDFs saved here
```

---

## ⚙️ Prerequisites

| Requirement | Details |
|---|---|
| **OS** | Windows 10 / 11 |
| **Compiler** | MinGW-w64 g++ (with C++17 support) |
| **SQLite3** | `sqlite3.dll` included in repo |
| **SumatraPDF** | Download from [sumatrapdfreader.org](https://www.sumatrapdfreader.org/download-free-pdf-viewer) |

> Make sure `g++` is in your system PATH. Test with `g++ --version` in Command Prompt.

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/GangavaramVenkatanatha/Sumatra-PDF-Fuzzer.git
cd Sumatra-PDF-Fuzzer
```

### 2. Place Required Files

Copy `SumatraPDF.exe` into the project root folder (same folder as `server.exe`):

```
project-root\
  ├── SumatraPDF.exe    ← copy here
  ├── sqlite3.dll
  ├── fuzzer.exe        ← after compiling
  ├── server.exe        ← after compiling
  └── index.html
```

### 3. Add Seed PDFs

Place at least one valid PDF into the seeds folder:

```
inputs\seeds\sample.pdf

If you need the seed files(inputs) you have them in the releases of this repository, named as inputs... As it is large i have uploaded it in the releases section.
```

> The fuzzer will not start without at least one seed PDF.

### 4. Compile the Fuzzer

```bash
g++ -O2 fuzzer_final.cpp -o fuzzer.exe -lsqlite3 -lpsapi
```

### 5. Compile the Server

```bash
g++ -O2 server.cpp -o server.exe -L. -lsqlite3 -lws2_32
```

### 6. Start the Server

```bash
server.exe
```

Expected output:
```
============================================
 FUZZER WEB SERVER  --  C++ Backend
============================================
[SERVER] Database connected: outputs/fuzzing.db
[SERVER] Running on http://localhost:8080
[SERVER] Press Ctrl+C to stop
```

### 7. Open the Dashboard

Open your browser and navigate to:

```
http://localhost:8080
```

The status indicator should turn **🟢 green**.

### 8. Start Fuzzing

1. *(Optional)* Upload additional seed PDFs using the **Upload Seed Files** panel
2. Set the **SumatraPDF Path** (default: `SumatraPDF.exe` if it's in the same folder)
3. Set the number of **Iterations** (default: 1000)
4. Click **🚀 Start Fuzzing**

---

## 🖥️ Running from Command Line (No UI)

You can run the fuzzer directly without the server:

```bash
# Default — 10,000 iterations, auto-detects SumatraPDF
fuzzer.exe

# Custom SumatraPDF path
fuzzer.exe "C:\Program Files\SumatraPDF\SumatraPDF.exe"

# Custom path + custom iteration count
fuzzer.exe "C:\Program Files\SumatraPDF\SumatraPDF.exe" 5000
```

---

## 📊 Understanding the Results

### Severity Levels

| Severity | Meaning | Saved? |
|---|---|---|
| `REAL_CRASH` | Memory-safety violation — AV, stack overflow, heap corruption | ✅ Yes |
| `EXCEPTION` | Unhandled exception (breakpoint, single-step) | ✅ Yes |
| `LOAD_ERROR` | SumatraPDF rejected/couldn't parse the PDF (exit code 1) | ✅ Yes |
| `ABNORMAL` | OS-level failure — DLL not found, bad path, access denied | ❌ No |
| `TIMEOUT` | Process hung past the 3-second timeout | ❌ No |

### Crash Files

All saved crashes are in `outputs/crashes/` named like:
```
seed_REAL_CRASH_MALICIOUS_iter4521.pdf
seed_LOAD_ERROR_iter892.pdf
```

### Database

Query the database directly with any SQLite browser:
```sql
-- All real security crashes
SELECT * FROM crashes WHERE severity IN ('REAL_CRASH', 'EXCEPTION');

-- All malicious PDFs that caused a crash
SELECT * FROM crashes WHERE is_malicious = 1;

-- Session history
SELECT * FROM sessions ORDER BY id DESC;
```

---

## 🛠️ Troubleshooting

| Problem | Fix |
|---|---|
| `sqlite3.dll not found` | Make sure `sqlite3.dll` is in the same folder as `server.exe` and `fuzzer.exe` |
| `🔴 Server Offline` in browser | Make sure `server.exe` is still running in the CMD window |
| Fuzzer won't start from UI | Confirm `fuzzer.exe` and `SumatraPDF.exe` are in the same folder as `server.exe` |
| No seed files error | Add at least one valid `.pdf` to `inputs/seeds/` |
| Port 8080 already in use | Kill any existing `server.exe` process in Task Manager, then restart |
| `SumatraPDF.exe not found` | Enter the full path in the UI field, e.g. `C:\Program Files\SumatraPDF\SumatraPDF.exe` |
| Database shows empty after restart | This is expected — see note below |

> **Note on database persistence:** Each fuzzing session currently resets the database on start. To preserve crash history across sessions, remove the `DROP TABLE` lines in `fuzzer_final.cpp`'s `DatabaseManager::initialize()` before compiling.

---

## 📄 License

This project is for educational and research purposes.  
Use responsibly and only against software you have permission to test.

---

## 🙏 Acknowledgements

- [SumatraPDF](https://www.sumatrapdfreader.org/) — the fuzzing target
- [SQLite](https://www.sqlite.org/) — embedded database
- [WinSock2](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page-2) — Windows networking API
