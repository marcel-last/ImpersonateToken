# Windows Token Impersonation Utility
## Overview
This C++ program is a demonstration tool designed to showcase Windows Token Impersonation. It attempts to hijack the security context (token) of a running process—typically a high-privilege system process like winlogon.exe (which runs as SYSTEM)—and use that token to launch a new executable (default: cmd.exe).

The key Windows APIs used are:
1. `SetPrivilege`: To enable `SeDebugPrivilege` and `SeImpersonatePrivilege` in the current process.
1. `OpenProcess` and `OpenProcessToken`: To gain access to the target process's token.
1. `DuplicateTokenEx`: To create a duplicatable impersonation token (_TokenImpersonation_).
1. `EnableAllPrivilegesOnToken`: To ensure all available privileges are enabled on the duplicated token before launching the process.
1. `CreateProcessWithTokenW`: To launch the new executable under the stolen token's security context.

## Usage
The program supports two optional command-line arguments: the path to the executable to run, and the PID of the target process to impersonate.

### Syntax
```
impersonate_token.exe [<EXECUTABLE_PATH>] [--pid <TARGET_PID>]
```

### Examples
| Command | Description |
|---------|-------------|
|`./impersonate_system.exe`|**Default behavior:** Attempts to impersonate the token of (default) process _winlogon.exe_ token and launch _C:\Windows\System32\cmd.exe_.|
|`./impersonate_system.exe --pid 1234`|Impersonates the token of process ID 1234 and launches _C:\Windows\System32\cmd.exe_.|
|`./impersonate_system.exe C:\tools\powershell.exe`|Impersonates the token of (default) process _winlogon.exe_ and launches _C:\tools\powershell.exe_.|
|`./impersonate_system.exe C:\tools\powershell.exe --pid 1234`|Impersonates the token of process  ID 1234 and launches _C:\tools\powershell.exe_.|

## Requirements and Limitations
###  Security Context (MUST RUN AS ELEVATED)
This program must be executed from an Elevated Command Prompt or Elevated PowerShell (Run as Administrator).
Running the program from a standard, non-elevated user context will fail because the operating system will deny the permission checks for critical steps.

### Required Privileges
For the process to succeed, the token of the calling process (i.e., the shell running impersonate_system.exe) must have the following privileges assigned (and the program will automatically attempt to enable them):
1. `SeDebugPrivilege`: Required to open high-privilege target processes (like_ winlogon.exe_) and their tokens.
1. `SeImpersonatePrivilege`: Required by the `CreateProcessWithTokenW` function to create a new process using an impersonation-level token. If the calling process's token is missing this privilege, the operation will fail with ERROR_PRIVILEGE_NOT_HELD (1314).

### Target Process Selection
- Default Target: The default target is winlogon.exe because it reliably runs as the SYSTEM user, which is often the highest possible security context on a Windows machine.
- Target Validity: If you specify a PID using the --pid switch, that process must exist and your calling process must have sufficient access rights (hence the need for `SeDebugPrivilege`) to query and duplicate its token.
