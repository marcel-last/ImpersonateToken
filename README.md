# ImpersonateToken

> [!CAUTION]
> All source code and content provided in this repository, including `impersonate_token.cpp` and related documentation, is intended solely for educational, training, research, and authorized development purposes. This code demonstrates security concepts and Windows API usage related to process token manipulation and privilege escalation within controlled, authorized environments.
> 
> By compiling, executing, or otherwise utilizing this code, you explicitly agree to assume all associated risks and full responsibility for any consequences. You are responsible for ensuring your actions comply with all applicable local, state, and international laws, rules, and regulations, and that you have explicit, written authorization to test or run this code on any target system.

## Overview
This C++ program is a demonstration tool designed to showcase Windows Token Impersonation. It attempts to hijack the security context (token) of a running process (typically a high-privilege system process) like _winlogon.exe_ (which runs as SYSTEM) and use that token to launch a new executable (default: `C:\Windows\System32\cmd.exe`).

The key Windows APIs used are:
1. `SetPrivilege`: To enable _SeDebugPrivilege_ and _SeImpersonatePrivilege_ in the current process.
1. `OpenProcess` and `OpenProcessToken`: To gain access to the target process's token.
1. `DuplicateTokenEx`: To create a duplicatable impersonation token (_TokenImpersonation_).
1. `EnableAllPrivilegesOnToken`: To ensure all available privileges are enabled on the duplicated token before launching the process.
1. `CreateProcessWithTokenW`: To launch the new executable under the stolen token's security context.

## Compilation
### Microsoft Visual C++ compiler (cl)
```powershell
cl impersonate_token.cpp /EHsc /link Advapi32.lib
```
- `/EHsc`: Enables C++ exception handling.
- `/link Advapi32.lib`: Explicitly links against the `Advapi32.lib` library, which contains `LookupPrivilegeValueW`, `AdjustTokenPrivileges`, `LookupAccountSidW`, and other required security functions. The necessary `Kernel32.lib` functions are linked by default.

### GCC
If you use the MinGW or MinGW-w64 toolchain, you can compile with the GCC/G++ compiler.
```bash
g++ impersonate_token.cpp -o impersonate_token.exe -lkernel32 -ladvapi32
```
- `-o impersonate_system.exe`: Sets the output file name.
- `-lkernel32`: Links the necessary kernel functions (e.g., `CreateToolhelp32Snapshot`).
- `-ladvapi32`: Links the necessary advanced API functions (security and token operations).

## Usage
The program supports two optional command-line arguments: the path to the executable to run, and the PID of the target process to impersonate.

### Syntax
```
impersonate_token.exe [<EXECUTABLE_PATH>] [--pid <TARGET_PID>]
```

### Examples
| Command | Description |
|---------|-------------|
|`./impersonate_token.exe`|**Default behavior:** Attempts to impersonate the token of (default) process _winlogon.exe_ token and launch _C:\Windows\System32\cmd.exe_.|
|`./impersonate_token.exe --pid 1234`|Impersonates the token of process ID 1234 and launches _C:\Windows\System32\cmd.exe_.|
|`./impersonate_token.exe C:\tools\powershell.exe`|Impersonates the token of (default) process _winlogon.exe_ and launches _C:\tools\powershell.exe_.|
|`./impersonate_token.exe C:\tools\powershell.exe --pid 1234`|Impersonates the token of process  ID 1234 and launches _C:\tools\powershell.exe_.|

## Requirements and Limitations
###  Security Context (MUST RUN ELEVATED)
This program must be executed from an Elevated Command Prompt or Elevated PowerShell (Run as Administrator).
Running the program from a standard, non-elevated user context will fail because the operating system will deny the permission checks for critical steps.

### Required Privileges
For the process to succeed, the token of the calling process (i.e., the shell running **impersonate_token.exe**) must have the following privileges assigned (and the program will automatically attempt to enable them):
1. `SeDebugPrivilege`: Required to open high-privilege target processes (like _winlogon.exe_) and their tokens.
1. `SeImpersonatePrivilege`: Required by the _CreateProcessWithTokenW_ function to create a new process using an impersonation-level token. If the calling process's token is missing this privilege, the operation will fail with ERROR_PRIVILEGE_NOT_HELD (1314).

### Target Process Selection
- Default Target: The default target is winlogon.exe because it reliably runs as the SYSTEM user, which is often the highest possible security context on a Windows machine.
- Target Validity: If you specify a PID using the --pid switch, that process must exist and your calling process must have sufficient access rights (hence the need for `SeDebugPrivilege`) to query and duplicate its token.


## Disclaimer of Liability and Warranty

### Code Purpose and Intent
All source code and content provided in this repository, including `impersonate_token.cpp` and related documentation, is intended solely for educational, training, research, and authorized development purposes. This code demonstrates security concepts and Windows API usage related to process token manipulation and privilege escalation within controlled, authorized environments.

### Limitation of Liability
THE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
This includes, without limitation, any claim, damages, or liability related to:
- Misuse or Illegal Activity: Any unauthorized, illegal, or unethical use of this code, including attempts to gain unauthorized access to computer systems or violate any laws.
- Loss of Data or System Damage: Any loss of data, system disruption, or harm caused by running, compiling, or modifying the code.
- Failure to Obtain Legal Counsel: Any decisions made by the user based on the content of this code or its documentation without consulting qualified legal advice.

### User Responsibility and Assumption of Risk
By compiling, executing, or otherwise utilizing this code, you explicitly agree to assume all associated risks and full responsibility for any consequences. You are responsible for ensuring your actions comply with all applicable local, state, and international laws, rules, and regulations, and that you have explicit, written authorization to test or run this code on any target system.
