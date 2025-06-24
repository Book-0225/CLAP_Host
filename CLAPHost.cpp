#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <cstdint>
#include <algorithm>
#include <vector>
#include <functional>
#include <shellapi.h>
#include <tchar.h>

#include "clap/all.h"

#pragma comment(lib, "shell32.lib")

// -------------------
// DbgPrint デバッグロギングマクロ
// -------------------
#define MAX_STATE_DATA_LEN 66000
#ifdef _DEBUG
#define DbgPrint(format, ...)                                                                               \
    do                                                                                                      \
    {                                                                                                       \
        TCHAR *tszDbgBuffer = new TCHAR[MAX_STATE_DATA_LEN];                                                \
        if (tszDbgBuffer)                                                                                   \
        {                                                                                                   \
            _stprintf_s(tszDbgBuffer, MAX_STATE_DATA_LEN, _T("[CLAPHost] ") format _T("\n"), ##__VA_ARGS__); \
            OutputDebugString(tszDbgBuffer);                                                                \
            _tprintf(tszDbgBuffer);                                                                         \
            delete[] tszDbgBuffer;                                                                          \
        }                                                                                                   \
    } while (0)
#else
#define DbgPrint(format, ...)
#endif


// -------------------
// ユーティリティ
// -------------------

namespace Base64 {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    static inline bool is_base64(unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }

    std::string encode(const unsigned char* bytes_to_encode, size_t in_len) {
        std::string ret;
        size_t i = 0, j = 0;
        unsigned char char_array_3[3], char_array_4[4];

        while (in_len--) {
            char_array_3[i++] = *(bytes_to_encode++);
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;
                for (i = 0; (i < 4); i++) ret += base64_chars[char_array_4[i]];
                i = 0;
            }
        }
        if (i) {
            for (j = i; j < 3; j++) char_array_3[j] = '\0';
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for (j = 0; (j < i + 1); j++) ret += base64_chars[char_array_4[j]];
            while ((i++ < 3)) ret += '=';
        }
        return ret;
    }

    std::vector<BYTE> decode(const std::string& encoded_string) {
        size_t in_len = encoded_string.size();
        size_t i = 0, j = 0, in_ = 0;
        unsigned char char_array_4[4], char_array_3[3];
        std::vector<BYTE> ret;

        while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
            char_array_4[i++] = encoded_string[in_]; in_++;
            if (i == 4) {
                for (i = 0; i < 4; i++) char_array_4[i] = static_cast<unsigned char>(base64_chars.find(char_array_4[i]));
                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
                for (i = 0; (i < 3); i++) ret.push_back(char_array_3[i]);
                i = 0;
            }
        }
        if (i) {
            for (j = i; j < 4; j++) char_array_4[j] = 0;
            for (j = 0; j < 4; j++) char_array_4[j] = static_cast<unsigned char>(base64_chars.find(char_array_4[j]));
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
        }
        return ret;
    }
}

std::wstring s2ws(const std::string& s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    if (len == 0) return L"";
    std::wstring r(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &r[0], len);
    r.resize(wcslen(r.c_str()));
    return r;
}

std::string ws2s(const std::wstring& ws) {
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, NULL, 0, NULL, NULL);
    if (len == 0) return "";
    std::string r(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &r[0], len, NULL, NULL);
    r.resize(strlen(r.c_str()));
    return r;
}

std::vector<std::string> split_command(const std::string& s) {
    std::vector<std::string> tokens;
    std::string current_token;
    std::stringstream ss(s);
    bool in_quotes = false;
    char c;
    while (ss.get(c)) {
        if (c == '"') { in_quotes = !in_quotes; }
        else if (c == ' ' && !in_quotes) {
            if (!current_token.empty()) { tokens.push_back(current_token); current_token.clear(); }
        }
        else { current_token += c; }
    }
    if (!current_token.empty()) tokens.push_back(current_token);
    return tokens;
}

#pragma pack(push, 1)
struct AudioSharedData {
    double  sampleRate;
    int32_t numSamples;
    int32_t numChannels;
};
#pragma pack(pop)
class ClapHost;

// -------------------
// ClapHost クラス定義
// -------------------
class ClapHost {
public:
    ClapHost(HINSTANCE hInstance, uint64_t unique_id,
        const std::wstring& pipeNameBase, const std::wstring& shmNameBase,
        const std::wstring& eventReadyNameBase, const std::wstring& eventDoneNameBase);
    ~ClapHost();

    bool Initialize();
    void RunMessageLoop();
    void Cleanup();
    void RequestStop();
    void RequestPluginCallback();
    bool ResizeGui(uint32_t width, uint32_t height);

private:
    static DWORD WINAPI PipeThreadProc(LPVOID p) { ((ClapHost*)p)->HandlePipeCommands(); return 0; }
    static DWORD WINAPI AudioThreadProc(LPVOID p) { ((ClapHost*)p)->HandleAudioProcessing(); return 0; }
    static LRESULT CALLBACK MainThreadMsgWndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp);
    static LRESULT CALLBACK GuiWndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp);

    void HandlePipeCommands();
    void HandleAudioProcessing();
    void ProcessQueuedCommands();
    std::string ProcessCommand(const std::string& full_cmd);

    bool LoadPlugin(const std::string& path, double sampleRate, int32_t blockSize);
    void ReleasePlugin();
    std::string GetPluginState();
    bool SetPluginState(const std::string& state_b64);
    void ShowGui();
    void HideGui();
    void OnGuiClose();

    bool InitIPC();

    HINSTANCE m_hInstance;
    uint64_t m_uniqueId;
    std::atomic<bool> m_mainLoopRunning{ false }, m_threadsRunning{ false };

    HANDLE m_hPipeThread = nullptr, m_hAudioThread = nullptr;
    HANDLE m_hPipe = INVALID_HANDLE_VALUE, m_hShm = nullptr;
    void* m_pSharedMem = nullptr;
    AudioSharedData* m_pSharedHeader = nullptr;
    float* m_pInL = nullptr, * m_pInR = nullptr, * m_pOutL = nullptr, * m_pOutR = nullptr;
    HANDLE m_hEventClientReady = nullptr, m_hEventHostDone = nullptr;
    std::wstring m_pipeName, m_shmName, m_eventReadyName, m_eventDoneName;

    std::mutex m_commandMutex;
    std::vector<std::string> m_commandQueue;

    std::mutex m_syncMutex;
    std::condition_variable m_syncCv;
    std::function<std::string()> m_syncTask;
    std::string m_syncResult;
    std::mutex m_mainThreadCallbackMutex;
    std::atomic<bool> m_pluginCallbackPending{ false };
    clap_host* m_clapHost = nullptr;
    HMODULE m_hPluginModule = nullptr;
    const clap_plugin_entry* m_pPluginEntry = nullptr;
    const clap_plugin* m_pPlugin = nullptr;
    bool m_isPluginActive = false;
    const clap_plugin_state* m_pExtState = nullptr;
    const clap_plugin_gui* m_pExtGui = nullptr;

    HWND m_hGuiWindow = nullptr, m_hMainThreadMsgWindow = nullptr;
    static const UINT WM_APP_PROCESS_COMMANDS = WM_APP + 1;
};

ClapHost* g_pClapHost = nullptr;

// -------------------
// CLAP Host Callbacks Implementation
// -------------------
static void host_log_callback(const clap_host_t* host, clap_log_severity severity, const char* msg) {
    std::string prefix;
    switch (severity) {
    case CLAP_LOG_DEBUG:   prefix = "[PLUGIN-DEBUG] "; break;
    case CLAP_LOG_INFO:    prefix = "[PLUGIN-INFO] "; break;
    case CLAP_LOG_WARNING: prefix = "[PLUGIN-WARN] "; break;
    case CLAP_LOG_ERROR:   prefix = "[PLUGIN-ERROR] "; break;
    case CLAP_LOG_FATAL:   prefix = "[PLUGIN-FATAL] "; break;
    default:               prefix = "[PLUGIN-LOG] "; break;
    }
    DbgPrint(_T("%hs%hs"), prefix.c_str(), msg);
}

static const clap_host_log log_extension = { host_log_callback };

static void host_gui_resize_hints_changed(const clap_host_t* host) {
    DbgPrint(_T("Plugin GUI resize hints changed."));
}

static bool host_gui_request_resize(const clap_host_t* host, uint32_t width, uint32_t height) {
    if (host->host_data) {
        return static_cast<ClapHost*>(host->host_data)->ResizeGui(width, height);
    }
    return false;
}

static const clap_host_gui gui_extension = {
   host_gui_resize_hints_changed,
   host_gui_request_resize,
};

static const void* host_get_extension(const struct clap_host* host, const char* extension_id) {
    if (strcmp(extension_id, CLAP_EXT_LOG) == 0) {
        return &log_extension;
    }
    if (strcmp(extension_id, CLAP_EXT_GUI) == 0) {
        return &gui_extension;
    }
    return nullptr;
}

static void host_request_restart(const clap_host_t* host) {
    DbgPrint(_T("Plugin requested restart. (This is not fully implemented)"));
}

static void host_request_callback(const clap_host_t* host) {
    if (host->host_data) {
        static_cast<ClapHost*>(host->host_data)->RequestPluginCallback();
    }
}


// -------------------
// ClapHost クラス実装
// -------------------

ClapHost::ClapHost(HINSTANCE hInstance, uint64_t unique_id,
    const std::wstring& pipeNameBase, const std::wstring& shmNameBase,
    const std::wstring& eventReadyNameBase, const std::wstring& eventDoneNameBase)
    : m_hInstance(hInstance), m_uniqueId(unique_id) {
    wchar_t buf[MAX_PATH];
    swprintf_s(buf, MAX_PATH, L"%s_%llu", pipeNameBase.c_str(), m_uniqueId); m_pipeName = buf;
    swprintf_s(buf, MAX_PATH, L"%s_%llu", shmNameBase.c_str(), m_uniqueId); m_shmName = buf;
    swprintf_s(buf, MAX_PATH, L"%s_%llu", eventReadyNameBase.c_str(), m_uniqueId); m_eventReadyName = buf;
    swprintf_s(buf, MAX_PATH, L"%s_%llu", eventDoneNameBase.c_str(), m_uniqueId); m_eventDoneName = buf;
    m_clapHost = new clap_host;
}

ClapHost::~ClapHost() {
    Cleanup();
    delete m_clapHost;
    m_clapHost = nullptr;
}

bool ClapHost::Initialize() {
    if (!InitIPC()) { DbgPrint(_T("Initialize: InitIPC FAILED.")); return false; }

    m_threadsRunning = true;
    m_hPipeThread = CreateThread(nullptr, 0, PipeThreadProc, this, 0, nullptr);
    m_hAudioThread = CreateThread(nullptr, 0, AudioThreadProc, this, 0, nullptr);
    if (!m_hPipeThread || !m_hAudioThread) { DbgPrint(_T("Initialize: Failed to create worker threads.")); return false; }
    *m_clapHost = {
        CLAP_VERSION_INIT,
        this,
        "CLAP Host", "BOOK-0225", "", "0.0.1",
        host_get_extension,
        host_request_restart,
        nullptr,
        host_request_callback
    };

    return true;
}

void ClapHost::RunMessageLoop() {
    WNDCLASSW wc = {};
    wc.lpfnWndProc = MainThreadMsgWndProc;
    wc.hInstance = m_hInstance;
    wc.lpszClassName = L"ClapHostMsgWindowClass";
    RegisterClassW(&wc);
    m_hMainThreadMsgWindow = CreateWindowW(wc.lpszClassName, nullptr, 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, m_hInstance, this);

    MSG msg;
    m_mainLoopRunning = true;
    while (m_mainLoopRunning && GetMessage(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void ClapHost::Cleanup() {
    if (!m_threadsRunning.exchange(false)) return;

    m_mainLoopRunning = false;
    m_syncCv.notify_all();

    if (m_hPipe != INVALID_HANDLE_VALUE) { CancelIoEx(m_hPipe, NULL); CloseHandle(m_hPipe); m_hPipe = INVALID_HANDLE_VALUE; }
    if (m_hEventClientReady) SetEvent(m_hEventClientReady);
    if (m_hMainThreadMsgWindow) PostMessage(m_hMainThreadMsgWindow, WM_QUIT, 0, 0);

    if (m_hPipeThread) { WaitForSingleObject(m_hPipeThread, 2000); CloseHandle(m_hPipeThread); m_hPipeThread = nullptr; }
    if (m_hAudioThread) { WaitForSingleObject(m_hAudioThread, 2000); CloseHandle(m_hAudioThread); m_hAudioThread = nullptr; }

    ReleasePlugin();

    if (m_pSharedMem) UnmapViewOfFile(m_pSharedMem); m_pSharedMem = nullptr;
    if (m_hShm) CloseHandle(m_hShm); m_hShm = nullptr;
    if (m_hEventClientReady) CloseHandle(m_hEventClientReady); m_hEventClientReady = nullptr;
    if (m_hEventHostDone) CloseHandle(m_hEventHostDone); m_hEventHostDone = nullptr;
    if (m_hMainThreadMsgWindow) DestroyWindow(m_hMainThreadMsgWindow); m_hMainThreadMsgWindow = nullptr;

    DbgPrint(_T("Cleanup complete."));
}

void ClapHost::RequestStop() { m_mainLoopRunning = false; }
void ClapHost::RequestPluginCallback() {
    {
        std::lock_guard<std::mutex> lock(m_mainThreadCallbackMutex);
        m_pluginCallbackPending = true;
    }
    if (m_hMainThreadMsgWindow) {
        PostMessage(m_hMainThreadMsgWindow, WM_APP_PROCESS_COMMANDS, 0, 0);
    }
}


void ClapHost::HandlePipeCommands() {
    DbgPrint(_T("Pipe thread started."));
    while (m_threadsRunning) {
        BOOL connected = ConnectNamedPipe(m_hPipe, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            if (!m_threadsRunning) break;
            Sleep(100); continue;
        }

        DbgPrint(_T("Client connected to pipe."));
        char buffer[8192];
        DWORD bytesRead;
        while (m_threadsRunning) {
            BOOL success = ReadFile(m_hPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
            if (!success || bytesRead == 0) break;

            buffer[bytesRead] = '\0';
            std::string cmd(buffer);
            std::string response = ProcessCommand(cmd);

            DWORD bytesWritten;
            WriteFile(m_hPipe, response.c_str(), (DWORD)response.length(), &bytesWritten, nullptr);
        }
        DisconnectNamedPipe(m_hPipe);
        DbgPrint(_T("Client disconnected from pipe."));
    }
    DbgPrint(_T("Pipe thread finished."));
}

std::string ClapHost::ProcessCommand(const std::string& full_cmd) {
    std::string cmd = full_cmd;
    cmd.erase(cmd.find_last_not_of("\r\n") + 1);
    DbgPrint(_T("Received command: %hs"), cmd.c_str());

    if (cmd == "exit") {
        RequestStop();
        return "OK\n";
    }

    if (cmd == "get_state") {
        std::string result;
        bool success = false;
        {
            std::unique_lock<std::mutex> lock(m_syncMutex);
            m_syncTask = [this] { return GetPluginState(); };
            if (m_hMainThreadMsgWindow) PostMessage(m_hMainThreadMsgWindow, WM_APP_PROCESS_COMMANDS, 0, 0);

            m_syncCv.wait(lock, [this] { return !m_syncTask || !m_mainLoopRunning; });

            if (m_mainLoopRunning) {
                result = m_syncResult;
                success = true;
            }
        }
        if (success) {
            return "OK " + result + "\n";
        }
        else {
            return "Error: Host is shutting down\n";
        }
    }

    {
        std::lock_guard<std::mutex> lock(m_commandMutex);
        m_commandQueue.push_back(cmd);
    }
    if (m_hMainThreadMsgWindow) PostMessage(m_hMainThreadMsgWindow, WM_APP_PROCESS_COMMANDS, 0, 0);
    return "OK\n";
}

void ClapHost::ProcessQueuedCommands() {
    {
        std::unique_lock<std::mutex> lock(m_syncMutex);
        if (m_syncTask) {
            m_syncResult = m_syncTask();
            m_syncTask = nullptr;
            lock.unlock();
            m_syncCv.notify_one();
        }
    }
    bool callback_needed = false;
    {
        std::lock_guard<std::mutex> lock(m_mainThreadCallbackMutex);
        if (m_pluginCallbackPending) {
            callback_needed = true;
            m_pluginCallbackPending = false;
        }
    }
    if (callback_needed && m_pPlugin && m_pPlugin->on_main_thread) {
        DbgPrint(_T("Executing plugin's on_main_thread() callback."));
        m_pPlugin->on_main_thread(m_pPlugin);
    }

    std::vector<std::string> commandsToProcess;
    {
        std::lock_guard<std::mutex> lock(m_commandMutex);
        if (m_commandQueue.empty()) return;
        commandsToProcess.swap(m_commandQueue);
    }

    for (const auto& cmd_raw : commandsToProcess) {
        auto args = split_command(cmd_raw);
        if (args.empty()) continue;
        const auto& cmd = args[0];

        try {
            if (cmd == "load_plugin" || cmd == "load_and_set_state") {
                if (args.size() < 4) { DbgPrint(_T("Error: Not enough args for load")); continue; }
                std::string path = args[1];
                double sr = std::stod(args[2]);
                int32_t bs = std::stoi(args[3]);
                if (LoadPlugin(path, sr, bs)) {
                    if (cmd == "load_and_set_state" && args.size() >= 5) {
                        SetPluginState(args[4]);
                    }
                }
            }
            else if (cmd == "show_gui") {
                ShowGui();
            }
            else if (cmd == "hide_gui") {
                HideGui();
            }
        }
        catch (const std::exception& e) {
            DbgPrint(_T("Error processing command '%hs': %hs"), cmd_raw.c_str(), e.what());
        }
    }
}

static uint32_t dummy_event_list_size(const struct clap_input_events* list) { return 0; }
static const clap_event_header_t* dummy_event_list_get(const struct clap_input_events* list, uint32_t index) { return nullptr; }
static bool dummy_event_list_try_push(const struct clap_output_events* list, const clap_event_header_t* event) { return false; }
static const clap_input_events  g_dummy_input_events = { nullptr, dummy_event_list_size, dummy_event_list_get };
static const clap_output_events g_dummy_output_events = { nullptr, dummy_event_list_try_push };


void ClapHost::HandleAudioProcessing() {
    DbgPrint(_T("Audio thread started."));
    while (m_threadsRunning) {
        if (WaitForSingleObject(m_hEventClientReady, 100) != WAIT_OBJECT_0) continue;
        if (!m_threadsRunning) break;

        if (m_pPlugin && m_isPluginActive && m_pSharedHeader->numSamples > 0) {
            clap_process process = {};
            process.steady_time = 0;
            process.frames_count = m_pSharedHeader->numSamples;
            process.in_events = &g_dummy_input_events;
            process.out_events = &g_dummy_output_events;

            process.audio_inputs_count = m_pSharedHeader->numChannels > 0 ? 1 : 0;
            process.audio_outputs_count = m_pSharedHeader->numChannels > 0 ? 1 : 0;

            const float* inputs[2] = { m_pInL, m_pInR };
            float* outputs[2] = { m_pOutL, m_pOutR };

            clap_audio_buffer in_buf = {};
            in_buf.data32 = const_cast<float**>(inputs);
            in_buf.channel_count = m_pSharedHeader->numChannels;
            in_buf.latency = 0;

            clap_audio_buffer out_buf = {};
            out_buf.data32 = outputs;
            out_buf.channel_count = m_pSharedHeader->numChannels;
            out_buf.latency = 0;

            process.audio_inputs = &in_buf;
            process.audio_outputs = &out_buf;

            m_pPlugin->process(m_pPlugin, &process);
        }
        else {
            if (m_pSharedHeader->numSamples > 0) {
                if (m_pSharedHeader->numChannels >= 1) memcpy(m_pOutL, m_pInL, m_pSharedHeader->numSamples * sizeof(float));
                if (m_pSharedHeader->numChannels >= 2) memcpy(m_pOutR, m_pInR, m_pSharedHeader->numSamples * sizeof(float));
            }
        }
        SetEvent(m_hEventHostDone);
    }
    DbgPrint(_T("Audio thread finished."));
}


bool ClapHost::LoadPlugin(const std::string& path, double sampleRate, int32_t blockSize) {
    DbgPrint(_T("LoadPlugin on main thread: %hs"), path.c_str());
    ReleasePlugin();

    m_hPluginModule = LoadLibraryW(s2ws(path).c_str());
    if (!m_hPluginModule) {
        DbgPrint(_T("Error: LoadLibraryW failed. Path: %hs Code: %lu"), path.c_str(), GetLastError());
        return false;
    }
    DbgPrint(_T("LoadLibraryW successful."));

    clap_plugin_entry_t* entry_proc = (clap_plugin_entry_t*)GetProcAddress(m_hPluginModule, "clap_plugin_entry");
    if (!entry_proc) {
        DbgPrint(_T("Info: 'clap_plugin_entry' not found. Trying 'clap_entry'..."));
        entry_proc = (clap_plugin_entry_t*)GetProcAddress(m_hPluginModule, "clap_entry");
        if (!entry_proc) {
            DbgPrint(_T("Error: Neither 'clap_plugin_entry' nor 'clap_entry' were found."));
            ReleasePlugin();
            return false;
        }
    }
    DbgPrint(_T("Entry point found."));

    DbgPrint(_T("Calling entry->init()..."));
    if (!entry_proc->init(path.c_str())) {
        DbgPrint(_T("Error: entry->init() returned false."));
        ReleasePlugin();
        return false;
    }
    DbgPrint(_T("entry->init() successful."));
    m_pPluginEntry = entry_proc;

    const auto* factory = (const clap_plugin_factory_t*)m_pPluginEntry->get_factory(CLAP_PLUGIN_FACTORY_ID);
    if (!factory || factory->get_plugin_count(factory) == 0) { DbgPrint(_T("Error: No factory/plugins")); ReleasePlugin(); return false; }

    const clap_plugin_descriptor_t* desc = factory->get_plugin_descriptor(factory, 0);
    m_pPlugin = factory->create_plugin(factory, m_clapHost, desc->id);
    if (!m_pPlugin) { DbgPrint(_T("Error: Failed to create plugin")); ReleasePlugin(); return false; }

    if (m_pPlugin->init) {
        DbgPrint(_T("Calling plugin->init()..."));
        if (!m_pPlugin->init(m_pPlugin)) {
            DbgPrint(_T("Error: plugin->init() returned false."));
            ReleasePlugin();
            return false;
        }
        DbgPrint(_T("plugin->init() successful."));
    }

    m_pExtState = (const clap_plugin_state*)m_pPlugin->get_extension(m_pPlugin, CLAP_EXT_STATE);
    m_pExtGui = (const clap_plugin_gui*)m_pPlugin->get_extension(m_pPlugin, CLAP_EXT_GUI);

    DbgPrint(_T("Calling plugin->activate()..."));
    if (!m_pPlugin->activate(m_pPlugin, sampleRate, blockSize, blockSize)) {
        DbgPrint(_T("Error: activate failed"));
        ReleasePlugin();
        return false;
    }
    m_isPluginActive = true;
    DbgPrint(_T("plugin->activate() successful."));

    if (m_pPlugin->start_processing) {
        DbgPrint(_T("Calling plugin->start_processing()..."));
        if (!m_pPlugin->start_processing(m_pPlugin)) {
            DbgPrint(_T("Warning: plugin->start_processing() returned false."));
        }
        else {
            DbgPrint(_T("plugin->start_processing() successful."));
        }
    }

    DbgPrint(_T("Plugin loaded and initialized completely."));
    return true;
}

void ClapHost::ReleasePlugin() {
    DbgPrint(_T("Releasing plugin..."));
    HideGui();
    if (m_pPlugin) {
        if (m_isPluginActive && m_pPlugin->stop_processing) {
            m_pPlugin->stop_processing(m_pPlugin);
        }
        if (m_isPluginActive) {
            m_pPlugin->deactivate(m_pPlugin);
        }
        m_pPlugin->destroy(m_pPlugin);
    }
    if (m_pPluginEntry) m_pPluginEntry->deinit();
    if (m_hPluginModule) FreeLibrary(m_hPluginModule);

    m_hPluginModule = nullptr;
    m_pPluginEntry = nullptr;
    m_pPlugin = nullptr;
    m_isPluginActive = false;
    m_pExtState = nullptr;
    m_pExtGui = nullptr;
    DbgPrint(_T("Plugin released."));
}

std::string ClapHost::GetPluginState() {
    if (!m_pPlugin || !m_pExtState) return "";
    struct Ctx { std::vector<BYTE> data; };
    Ctx ctx;
    clap_ostream stream = { &ctx, [](const struct clap_ostream* stream, const void* buffer, uint64_t size) -> int64_t {
        auto* c = (Ctx*)stream->ctx;
        c->data.insert(c->data.end(), (const BYTE*)buffer, (const BYTE*)buffer + size);
        return size;
    } };
    if (m_pExtState->save(m_pPlugin, &stream)) {
        return Base64::encode(ctx.data.data(), ctx.data.size());
    }
    return "";
}

bool ClapHost::SetPluginState(const std::string& state_b64) {
    if (!m_pPlugin || !m_pExtState) return false;
    auto data = Base64::decode(state_b64);
    if (data.empty() && !state_b64.empty()) return false;
    struct Ctx { const std::vector<BYTE>* data; int64_t pos = 0; };
    Ctx ctx = { &data };
    clap_istream stream = { &ctx, [](const struct clap_istream* stream, void* buffer, uint64_t size) -> int64_t {
        auto* c = (Ctx*)stream->ctx;
        int64_t to_read = std::min((int64_t)size, (int64_t)c->data->size() - c->pos);
        if (to_read <= 0) return 0;
        memcpy(buffer, c->data->data() + c->pos, to_read);
        c->pos += to_read;
        return to_read;
    } };
    return m_pExtState->load(m_pPlugin, &stream);
}

void ClapHost::ShowGui() {
    if (m_hGuiWindow && IsWindow(m_hGuiWindow)) {
        ShowWindow(m_hGuiWindow, SW_SHOW);
        SetForegroundWindow(m_hGuiWindow);
        return;
    }
    if (!m_pPlugin || !m_pExtGui || !m_pExtGui->is_api_supported(m_pPlugin, CLAP_WINDOW_API_WIN32, false)) {
        DbgPrint(_T("GUI not available or not supported."));
        return;
    }

    DbgPrint(_T("Showing GUI"));
    WNDCLASSW wc = {};
    wc.lpfnWndProc = GuiWndProc;
    wc.hInstance = m_hInstance;
    wc.lpszClassName = L"ClapHostGuiWindowClass";
    RegisterClassW(&wc);

    m_hGuiWindow = CreateWindowExW(0, wc.lpszClassName, L"Plugin GUI", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, NULL, NULL, m_hInstance, this);
    if (!m_hGuiWindow) { DbgPrint(_T("Failed to create GUI window.")); return; }

    if (!m_pExtGui->create(m_pPlugin, CLAP_WINDOW_API_WIN32, false)) {
        DbgPrint(_T("Failed to create plugin GUI."));
        DestroyWindow(m_hGuiWindow);
        m_hGuiWindow = nullptr;
        return;
    }

    uint32_t w, h;
    if (m_pExtGui->get_size(m_pPlugin, &w, &h)) {
        RECT rc = { 0, 0, (LONG)w, (LONG)h };
        AdjustWindowRect(&rc, GetWindowLong(m_hGuiWindow, GWL_STYLE), FALSE);
        SetWindowPos(m_hGuiWindow, NULL, 0, 0, rc.right - rc.left, rc.bottom - rc.top, SWP_NOMOVE | SWP_NOZORDER);
    }

    clap_window win = {};
    win.api = CLAP_WINDOW_API_WIN32;
    win.win32 = (void*)m_hGuiWindow;
    m_pExtGui->set_parent(m_pPlugin, &win);
    m_pExtGui->show(m_pPlugin);
    ShowWindow(m_hGuiWindow, SW_SHOW);
}

bool ClapHost::ResizeGui(uint32_t width, uint32_t height) {
    if (!m_hGuiWindow || !IsWindow(m_hGuiWindow)) {
        return false;
    }
    DbgPrint(_T("Plugin requested GUI resize to %u x %u. Resizing window."), width, height);
    RECT rc = { 0, 0, (LONG)width, (LONG)height };
    AdjustWindowRect(&rc, GetWindowLong(m_hGuiWindow, GWL_STYLE), FALSE);
    SetWindowPos(m_hGuiWindow, NULL, 0, 0, rc.right - rc.left, rc.bottom - rc.top, SWP_NOMOVE | SWP_NOZORDER);
    return true;
}

void ClapHost::HideGui() {
    if (m_hGuiWindow) {
        DestroyWindow(m_hGuiWindow);
    }
}

void ClapHost::OnGuiClose() {
    DbgPrint(_T("Hiding GUI"));
    if (m_pExtGui && m_pPlugin) {
        m_pExtGui->hide(m_pPlugin);
        m_pExtGui->destroy(m_pPlugin);
    }
    m_hGuiWindow = nullptr;
    UnregisterClassW(L"ClapHostGuiWindowClass", m_hInstance);
}

LRESULT CALLBACK ClapHost::GuiWndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    ClapHost* host;
    if (msg == WM_CREATE) {
        host = (ClapHost*)((CREATESTRUCT*)lp)->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)host);
    }
    else {
        host = (ClapHost*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }
    if (host) {
        if (msg == WM_DESTROY) {
            host->OnGuiClose();
            SetWindowLongPtr(hWnd, GWLP_USERDATA, NULL);
        }
        else if (msg == WM_CLOSE) {
            return 0;
        }
    }
    return DefWindowProc(hWnd, msg, wp, lp);
}

LRESULT CALLBACK ClapHost::MainThreadMsgWndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    ClapHost* host;
    if (msg == WM_CREATE) {
        host = (ClapHost*)((CREATESTRUCT*)lp)->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)host);
    }
    else {
        host = (ClapHost*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }
    if (host && msg == WM_APP_PROCESS_COMMANDS) {
        host->ProcessQueuedCommands();
        return 0;
    }
    return DefWindowProc(hWnd, msg, wp, lp);
}

bool ClapHost::InitIPC() {
    DbgPrint(_T("InitIPC Pipe: %hs"), ws2s(m_pipeName).c_str());
    m_hPipe = CreateNamedPipeW(m_pipeName.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 8192, 8192, 0, nullptr);
    if (m_hPipe == INVALID_HANDLE_VALUE) return false;

    const size_t shm_size = sizeof(AudioSharedData) + 4 * 2048 * sizeof(float);
    m_hShm = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, (DWORD)shm_size, m_shmName.c_str());
    if (!m_hShm) return false;

    m_pSharedMem = MapViewOfFile(m_hShm, FILE_MAP_ALL_ACCESS, 0, 0, shm_size);
    if (!m_pSharedMem) return false;

    m_pSharedHeader = (AudioSharedData*)m_pSharedMem;
    m_pInL = (float*)((char*)m_pSharedMem + sizeof(AudioSharedData));
    m_pInR = m_pInL + 2048; m_pOutL = m_pInR + 2048; m_pOutR = m_pOutL + 2048;

    m_hEventClientReady = CreateEventW(nullptr, FALSE, FALSE, m_eventReadyName.c_str());
    m_hEventHostDone = CreateEventW(nullptr, FALSE, FALSE, m_eventDoneName.c_str());
    return m_hEventClientReady && m_hEventHostDone;
}

// -------------------
// WinMain エントリポイント
// -------------------
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
#ifdef _DEBUG
    AllocConsole(); FILE* c; freopen_s(&c, "CONOUT$", "w", stdout);
#endif
    DbgPrint(_T("Application starting..."));

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) { DbgPrint(_T("Fatal: Failed to parse command line")); return 1; }

    uint64_t uid = GetCurrentProcessId();
    std::wstring pipeBase = L"\\\\.\\pipe\\ClapBridge", shmBase = L"Local\\ClapSharedAudio";
    std::wstring readyBase = L"Local\\ClapClientReady", doneBase = L"Local\\ClapHostDone";

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        try {
            if (arg == L"-uid" && i + 1 < argc) uid = std::stoull(argv[++i]);
            else if (arg == L"-pipe" && i + 1 < argc) pipeBase = argv[++i];
            else if (arg == L"-shm" && i + 1 < argc) shmBase = argv[++i];
            else if (arg == L"-event_ready" && i + 1 < argc) readyBase = argv[++i];
            else if (arg == L"-event_done" && i + 1 < argc) doneBase = argv[++i];
        }
        catch (const std::exception& e) {
            DbgPrint(_T("Error parsing command line args: %hs"), e.what());
        }
    }
    LocalFree(argv);

    g_pClapHost = new ClapHost(hInstance, uid, pipeBase, shmBase, readyBase, doneBase);

    if (g_pClapHost->Initialize()) {
        g_pClapHost->RunMessageLoop();
    }

    delete g_pClapHost;
    g_pClapHost = nullptr;

    DbgPrint(_T("Application finished."));
#ifdef _DEBUG
    if (c) fclose(c); FreeConsole();
#endif
    return 0;
}