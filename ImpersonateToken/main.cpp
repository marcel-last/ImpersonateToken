#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <cstdlib> // For strtoul and free/malloc
#include <sddl.h> // Required for ConvertSidToStringSidW (useful for debugging, though not strictly needed here)

// Function to enable a specific privilege in the current process's token
BOOL SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed. Error: " << GetLastError() << std::endl;
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, lpszPrivilege, &luid)) {
        std::cerr << "LookupPrivilegeValueW failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else {
        tp.Privileges[0].Attributes = 0;
    }

    // Enable the privilege
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        std::cerr << "AdjustTokenPrivileges failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        // This indicates the privilege is not assigned to the token at all.
        // Using std::wcout for correct display of the wide string privilege name.
        std::wcout << L"The current user context does not have the specified token privilege assigned: " << lpszPrivilege << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

// Function to find the PID of a process by name (e.g., "winlogon.exe")
DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

// Function to find the process name by PID
std::wstring GetProcessNameByPid(DWORD pid) {
    std::wstring processName = L"PID not found";
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == pid) {
                    processName = pe32.szExeFile;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return processName;
}

// Function to enable all privileges present in a given token handle
void EnableAllPrivilegesOnToken(HANDLE hToken) {
    PTOKEN_PRIVILEGES pTP = NULL;
    DWORD dwLength = 0;

    // 1. Get required buffer size for TokenPrivileges
    // First call to get the required size (expected to fail with ERROR_INSUFFICIENT_BUFFER)
    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLength) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Warning: GetTokenInformation failed to get required buffer size for token privileges. Error: " << GetLastError() << std::endl;
        return;
    }

    pTP = (PTOKEN_PRIVILEGES)malloc(dwLength);
    if (pTP == NULL) {
        std::cerr << "Warning: Failed to allocate memory for privileges list." << std::endl;
        return;
    }

    // 2. Retrieve the current privilege list
    if (!GetTokenInformation(hToken, TokenPrivileges, pTP, dwLength, &dwLength)) {
        std::cerr << "Warning: GetTokenInformation failed to retrieve privileges list. Error: " << GetLastError() << std::endl;
        free(pTP);
        return;
    }

    // 3. Set all privileges to SE_PRIVILEGE_ENABLED
    for (DWORD i = 0; i < pTP->PrivilegeCount; i++) {
        pTP->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
    }

    // 4. Apply the changes to the token
    if (!AdjustTokenPrivileges(hToken, FALSE, pTP, dwLength, NULL, NULL)) {
        std::cerr << "Warning: AdjustTokenPrivileges failed to enable all privileges on duplicated token. Error: " << GetLastError() << std::endl;
    }
    else {
        std::cout << "Successfully enabled " << pTP->PrivilegeCount << " privileges on the duplicated token." << std::endl;
    }

    // Cleanup
    free(pTP);
}

// Main logic to use a specific process's token and execute a process with it
void RunCmdAsSystem(DWORD targetPid, const wchar_t* targetProcessName, const wchar_t* commandLineW) {
    // 1. Enable SeDebugPrivilege to open the target process
    if (!SetPrivilege(SE_DEBUG_NAME, TRUE)) {
        std::cerr << "Failed to enable SeDebugPrivilege. Cannot proceed." << std::endl;
        return;
    }

    // 2. Enable SeImpersonatePrivilege. This is required for creating a process 
    // using an impersonation token (via DuplicateTokenEx or CreateProcessWithTokenW).
    if (!SetPrivilege(SE_IMPERSONATE_NAME, TRUE)) {
        std::cerr << "Failed to enable SeImpersonatePrivilege. Cannot proceed (token must possess this privilege)." << std::endl;
        // Cleanup existing enabled privilege before exit
        SetPrivilege(SE_DEBUG_NAME, FALSE);
        return;
    }

    std::wcout << L"Target PID: " << targetPid << L" (" << targetProcessName << L")" << std::endl;
    std::wcout << L"Command: " << commandLineW << std::endl;

    // 3. Open the target process and its token
    // We need PROCESS_QUERY_INFORMATION to open the process handle
    HANDLE hTargetProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (hTargetProcess == NULL) {
        std::cerr << "OpenProcess failed. Error: " << GetLastError() << std::endl;
        // Cleanup privileges before exit
        SetPrivilege(SE_DEBUG_NAME, FALSE);
        SetPrivilege(SE_IMPERSONATE_NAME, FALSE);
        return;
    }

    HANDLE hProcessToken = NULL;
    // We need TOKEN_DUPLICATE and TOKEN_QUERY for the source token
    if (!OpenProcessToken(hTargetProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hProcessToken)) {
        std::cerr << "OpenProcessToken failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hTargetProcess);
        // Cleanup privileges before exit
        SetPrivilege(SE_DEBUG_NAME, FALSE);
        SetPrivilege(SE_IMPERSONATE_NAME, FALSE);
        return;
    }

    // 4. Duplicate the token to create an impersonation token
    // Using TokenImpersonation removes the dependency on SeAssignPrimaryTokenPrivilege
    // Requesting TOKEN_ALL_ACCESS here grants us TOKEN_ADJUST_PRIVILEGES on the duplicate.
    HANDLE hDuplicatedToken = NULL;
    if (!DuplicateTokenEx(
        hProcessToken,
        TOKEN_ALL_ACCESS,
        NULL,
        SecurityImpersonation,
        TokenImpersonation, // Changed to TokenImpersonation
        &hDuplicatedToken))
    {
        std::cerr << "DuplicateTokenEx failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcessToken);
        CloseHandle(hTargetProcess);
        // Cleanup privileges before exit
        SetPrivilege(SE_DEBUG_NAME, FALSE);
        SetPrivilege(SE_IMPERSONATE_NAME, FALSE);
        return;
    }

    // --- Start of logic to display username ---

    DWORD dwLength = 0;
    PTOKEN_USER pTokenUser = NULL;
    DWORD dwUsernameSize = 256;
    DWORD dwDomainSize = 256;
    WCHAR wszUsername[256] = { 0 };
    WCHAR wszDomain[256] = { 0 };
    SID_NAME_USE snu;
    bool usernameRetrieved = false;

    // 1. Get required buffer size for TokenUser
    GetTokenInformation(hDuplicatedToken, TokenUser, NULL, 0, &dwLength);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && dwLength > 0) {
        pTokenUser = (PTOKEN_USER)malloc(dwLength);
        if (pTokenUser != NULL) {
            // 2. Get TokenUser information
            if (GetTokenInformation(hDuplicatedToken, TokenUser, pTokenUser, dwLength, &dwLength)) {
                // 3. Lookup the account name from the SID
                if (LookupAccountSidW(
                    NULL,
                    pTokenUser->User.Sid,
                    wszUsername, &dwUsernameSize,
                    wszDomain, &dwDomainSize,
                    &snu))
                {
                    std::wcout << L"Successfully duplicated target token for user: "
                        << wszDomain << L"\\" << wszUsername << L" (IMPERSONATION token)." << std::endl;
                    usernameRetrieved = true;
                }
            }
            free(pTokenUser);
        }
    }

    if (!usernameRetrieved) {
        // Fallback if the retrieval failed
        std::cout << "Successfully duplicated target token as IMPERSONATION token." << std::endl;
    }

    // --- End of logic to display username ---

    // *** NEW STEP: Enable all privileges on the duplicated token BEFORE process creation. ***
    EnableAllPrivilegesOnToken(hDuplicatedToken);

    // 5. Setup structures for CreateProcessWithTokenW
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    si.cb = sizeof(STARTUPINFOW);
    si.lpDesktop = (LPWSTR)L"WinSta0\\Default"; // Important for GUI visibility

    ZeroMemory(&pi, sizeof(pi));

    // 6. Execute command using the duplicated token
    // We must duplicate the string as CreateProcessWithTokenW modifies the buffer
    LPWSTR commandLine = _wcsdup(commandLineW);

    BOOL result = CreateProcessWithTokenW(
        hDuplicatedToken,   // The impersonation token (now with all privileges enabled)
        LOGON_WITH_PROFILE, // Loads user profile for proper environment setup
        NULL,               // Application Name (NULL allows the command line to specify the path)
        commandLine,        // Command line (cmd.exe or user-specified path)
        CREATE_NEW_CONSOLE, // Creation flags
        NULL,               // Environment
        NULL,               // Current directory
        &si,                // STARTUPINFO
        &pi                 // PROCESS_INFORMATION
    );

    if (result) {
        std::cout << "SUCCESS: Process launched in the target user context using CreateProcessWithTokenW." << std::endl;
        // Display the PID of the newly created process
        std::cout << "Process ID of the spawned process: " << pi.dwProcessId << std::endl;

        // Remove the call that was causing ERROR_ACCESS_DENIED:
        // EnableAllPrivilegesInNewProcess(pi.hProcess); 

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        // This is the common failure point if SeImpersonatePrivilege is missing/disabled/not held,
        // or if the desktop/window station cannot be accessed.
        std::cerr << "FAILED to launch process with CreateProcessWithTokenW. Error: " << GetLastError() << "." << std::endl;
    }

    // Cleanup
    free(commandLine); // Use free() because _wcsdup() was used
    CloseHandle(hDuplicatedToken);
    CloseHandle(hProcessToken);
    CloseHandle(hTargetProcess);

    // Disable privileges
    SetPrivilege(SE_IMPERSONATE_NAME, FALSE);
    SetPrivilege(SE_DEBUG_NAME, FALSE);
}

// Entry point with command-line arguments
int main(int argc, char* argv[]) {
    DWORD targetPid = 0;
    const wchar_t* defaultProcessName = L"winlogon.exe";
    const wchar_t* defaultExecutablePath = L"C:\\Windows\\System32\\cmd.exe";
    bool pidSpecified = false;

    // Default executable to run
    std::wstring executablePath = defaultExecutablePath;
    std::wstring targetProcessName = defaultProcessName; // Initialize default name

    // Check argv[1] for executable path if it's not the --pid switch
    if (argc > 1 && _stricmp(argv[1], "--pid") != 0) {
        // Argument 1 is assumed to be the executable path

        // Convert char* (argv[1]) to std::wstring (executablePath)
        int len = MultiByteToWideChar(CP_ACP, 0, argv[1], -1, NULL, 0);
        if (len > 0) {
            wchar_t* wpath = new wchar_t[len];
            MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wpath, len);
            executablePath = wpath;
            delete[] wpath;
        }
    }

    // Parse arguments for the --pid switch (checks all arguments)
    for (int i = 1; i < argc; ++i) {
        if (_stricmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            targetPid = strtoul(argv[i + 1], NULL, 10);
            pidSpecified = true;

            // --- MODIFIED LOGIC: Look up the process name by PID ---
            targetProcessName = GetProcessNameByPid(targetPid);
            // --------------------------------------------------------

            i++; // Skip the next argument (the PID value)
            break; // Stop parsing after finding PID
        }
    }

    if (!pidSpecified) {
        std::wcout << L"No PID specified. Defaulting to targeting: " << defaultProcessName << L"..." << std::endl;
        targetPid = GetProcessIdByName(defaultProcessName);
    }

    if (targetPid == 0) {
        if (pidSpecified) {
            std::wcerr << L"Error: Invalid or non-existent PID provided: " << targetProcessName << L"." << std::endl;
        }
        else {
            std::wcerr << L"Error: Could not find the default process (" << defaultProcessName << L"). Exiting." << std::endl;
        }
        std::cerr << "Usage: " << argv[0] << " [<ExecutablePath>] [--pid <Target_PID>]" << std::endl;
        std::wcerr << L"Default executable: " << defaultExecutablePath << L". Default target: " << defaultProcessName << L"." << std::endl;
        return 1;
    }

    RunCmdAsSystem(targetPid, targetProcessName.c_str(), executablePath.c_str());
    return 0;
}

