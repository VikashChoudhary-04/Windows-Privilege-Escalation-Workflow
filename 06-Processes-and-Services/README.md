# Processes & Services

Windows processes and services are common components in privilege escalation investigations.

A process may execute with a different security context from the current user. A Windows service may also execute as a highly privileged account while relying on executables, DLLs, configuration files, or directories that may have weaker permissions.

The objective of this stage is to answer:

> **What is running, under which security context, how is it launched, and can the current user influence anything involved in that execution?**

---

## 1. Investigation Model

Use the following model when investigating a process or service:

```text
Process / Service
        ↓
Execution Account
        ↓
Executable Path
        ↓
Parent Directory
        ↓
Required DLLs / Files
        ↓
Permissions / ACLs
        ↓
Configuration
        ↓
Can Current User Influence It?
        ↓
Privilege Boundary
```

A process running as `SYSTEM` is not automatically vulnerable.

The important question is whether a lower-privileged user can influence something that the privileged process trusts.

---

# Processes

## 2. Enumerate Running Processes

Start with:

```cmd id="n5c1je"
tasklist
```

For additional information:

```cmd id="j5c4f7"
tasklist /v
```

PowerShell:

```powershell id="9u2v2p"
Get-Process
```

Useful information includes:

* Process name.
* PID.
* Session.
* Memory usage.
* Process owner where available.
* Application identity.

---

## 3. Identify Process Ownership

The process owner is important because it tells you which security context the process operates under.

PowerShell can be used to query process ownership:

```powershell id="3k1d9b"
Get-CimInstance Win32_Process |
Select-Object ProcessId,Name,ExecutablePath
```

To retrieve ownership information for a specific process:

```powershell id="r8l1vz"
Get-CimInstance Win32_Process -Filter "ProcessId=<PID>" |
Invoke-CimMethod -MethodName GetOwner
```

Replace `<PID>` with the relevant process ID.

The key relationship is:

```text id="qz4f7x"
Process
   ↓
Owner
   ↓
Privilege Context
```

---

## 4. Identify High-Privilege Processes

Look for processes running under contexts such as:

```text id="m6x3sf"
SYSTEM
LOCAL SERVICE
NETWORK SERVICE
Administrator
Other privileged service accounts
```

Examples may include:

```text id="8j1m0u"
services.exe
lsass.exe
winlogon.exe
svchost.exe
```

These processes are security-sensitive, but their presence alone does not establish an escalation opportunity.

Do not interact with sensitive processes unnecessarily.

---

## 5. Investigate Interesting Processes

When a process looks relevant, record:

```text id="0t8r5g"
Process:
PID:
Owner:
Executable:
Arguments:
Parent Process:
Session:
```

Then ask:

```text id="8ly7i8"
What starts this process?
What account does it run under?
Where is the executable?
Who can modify it?
What configuration does it use?
Does it load additional files?
```

---

## 6. Determine Executable Paths

Finding the executable path is essential.

PowerShell:

```powershell id="tx0zgj"
Get-CimInstance Win32_Process |
Select-Object Name,ProcessId,ExecutablePath
```

For a specific process:

```powershell id="4z6w2h"
Get-CimInstance Win32_Process -Filter "ProcessId=<PID>" |
Select-Object Name,ProcessId,ExecutablePath,CommandLine
```

The path should then be investigated for permissions.

Example:

```text id="y5wqf2"
C:\Program Files\Example\service.exe
```

Do not stop at the executable itself.

Also inspect:

```text id="2k2j0a"
Executable
   ↓
Parent Directory
   ↓
Parent Directories
   ↓
Related DLLs
   ↓
Configuration Files
```

---

## 7. Process Command Lines

Command-line arguments can reveal:

* Configuration files.
* Service modes.
* Custom scripts.
* Credentials accidentally supplied as arguments.
* Alternate executable paths.
* Application-specific parameters.

PowerShell:

```powershell id="qg2n2d"
Get-CimInstance Win32_Process |
Select-Object ProcessId,Name,CommandLine
```

Treat command-line output as potentially sensitive.

Do not publish credentials or secrets discovered there.

---

## 8. Parent-Child Relationships

Understanding process hierarchy can reveal how a privileged process was launched.

PowerShell:

```powershell id="q4g2fs"
Get-CimInstance Win32_Process |
Select-Object ProcessId,ParentProcessId,Name
```

Conceptually:

```text id="x0gq7v"
Parent Process
      ↓
Child Process
      ↓
Execution Context
```

Ask:

```text id="0h5cga"
Who launches the process?
Under which account?
What executable is launched?
What arguments are supplied?
Can the current user influence the launch chain?
```

---

# Services

## 9. Enumerate Services

Start with:

```cmd id="75y8de"
sc query state= all
```

PowerShell:

```powershell id="0g1v3m"
Get-Service
```

For configuration details:

```cmd id="gq0z8s"
sc qc <service_name>
```

Example:

```cmd id="t0v8yd"
sc qc ExampleService
```

---

## 10. Service Information to Record

For each interesting service, record:

```text id="t9u4s7"
Service Name:
Display Name:
State:
Start Type:
Start Account:
Binary Path:
Dependencies:
Service Type:
```

The most important relationship is:

```text id="gk6h1x"
Service
   ↓
Start Account
   ↓
Binary Path
   ↓
Permissions
```

---

## 11. Identify Service Accounts

A service may run as:

```text id="v2s8l3"
LocalSystem
LocalService
NetworkService
Administrator
Domain Account
Custom Service Account
```

The account matters because it determines the security context of the service process.

For example:

```text id="j3q9r5"
Service
   ↓
LocalSystem
   ↓
Privileged Process
```

Now investigate whether the lower-privileged user can influence anything the service executes.

---

## 12. Service Configuration

Use:

```cmd id="u9v8c1"
sc qc <service_name>
```

Inspect:

* `BINARY_PATH_NAME`
* `SERVICE_START_NAME`
* Start type.
* Dependencies.

PowerShell:

```powershell id="8k0g6r"
Get-CimInstance Win32_Service |
Select-Object Name,StartName,State,StartMode,PathName
```

---

## 13. Service Binary Path

The binary path is one of the most important fields.

Example:

```text id="8m4j7c"
BINARY_PATH_NAME:
C:\Program Files\Example Service\service.exe
```

Now investigate:

```text id="t3b9p1"
Can the current user modify service.exe?
        ↓
Can the current user modify its directory?
        ↓
Can the current user modify a required DLL?
        ↓
Can the current user modify service configuration?
```

This creates the core service escalation decision tree.

---

## 14. Check Executable Permissions

Once an interesting executable is identified:

```cmd id="3x6v6k"
icacls "C:\Path\service.exe"
```

Example:

```text id="gq5z8m"
C:\Path\service.exe
    BUILTIN\Users:(RX)
    BUILTIN\Administrators:(F)
    NT AUTHORITY\SYSTEM:(F)
```

Interpret the permissions carefully.

Common permissions include:

```text id="9r9j2w"
F   Full access
M   Modify
RX  Read & execute
R   Read
W   Write
```

The important question is:

> **Can the current user modify the executable or otherwise influence what the privileged service executes?**

---

## 15. Check Directory Permissions

Checking only the executable is insufficient.

For example:

```text id="4z9q1m"
C:\Program Files\Example\
    service.exe
```

Check the directory:

```cmd id="2f9t5m"
icacls "C:\Program Files\Example"
```

A user may be unable to modify the executable directly but may be able to modify:

* Its parent directory.
* A dependency.
* A configuration file.
* A DLL.
* Another file used during execution.

---

## 16. Check Parent Directories

Trace the entire path:

```text id="w7t0az"
C:\
 ↓
Program Files\
 ↓
Example\
 ↓
service.exe
```

A writable parent directory can be relevant even if the executable itself is protected.

Check each relevant directory with:

```cmd id="4qz2w8"
icacls "C:\Path\To\Directory"
```

Do not assume that write access automatically results in escalation.

Determine what the service actually does with the writable resource.

---

## 17. Service Control Permissions

Executable permissions are only one part of service security.

A service itself has a security descriptor controlling who can perform actions such as:

* Start.
* Stop.
* Change configuration.
* Delete.
* Query.
* Control.

Inspect the service security descriptor where appropriate:

```cmd id="y4q5w9"
sc sdshow <service_name>
```

The resulting SDDL can be difficult to interpret manually.

The important question is:

> **Can the current user modify the service configuration or control it in a way that affects privileged execution?**

---

## 18. Unquoted Service Paths

An unquoted service path can become relevant when a service executable path contains spaces.

Example:

```text id="9v4q4e"
C:\Program Files\Example Service\service.exe
```

If the configured path is improperly quoted, Windows executable resolution behavior may create ambiguity.

The investigation should determine:

```text id="y2f6j7"
Does the path contain spaces?
        ↓
Is the executable path properly quoted?
        ↓
Which candidate paths could Windows resolve?
        ↓
Can the current user write to a relevant location?
        ↓
Would the service actually execute that location?
```

An unquoted path alone is not sufficient evidence of exploitation.

---

## 19. Service DLL Dependencies

A service may load additional DLLs.

Investigate:

```text id="p1x0g3"
Service
   ↓
Executable
   ↓
DLL Dependencies
   ↓
DLL Search Behavior
   ↓
Writable Location?
```

Potentially relevant situations include:

* Missing DLLs.
* Search-order behavior.
* Writable directories.
* Application-specific loading behavior.

DLL loading must be validated against the actual executable and environment.

---

## 20. Service Registry Configuration

Services are represented in the registry.

The primary service configuration location is:

```text id="5i3jpk"
HKLM\SYSTEM\CurrentControlSet\Services\
```

For example:

```cmd id="8i7x5m"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<service_name>"
```

Relevant values may include:

```text id="4o3m7s"
ImagePath
ObjectName
Start
Type
DependOnService
```

Registry permissions should be investigated separately.

Detailed registry analysis belongs in:

```text id="k8g6c0"
09-Registry/
```

---

## 21. Service Dependencies

A service may depend on another service.

Inspect:

```cmd id="m2z6b9"
sc qc <service_name>
```

Look for:

```text id="l7x9v4"
DEPENDENCIES
```

The dependency chain may look like:

```text id="7n1f0p"
Service A
   ↓
Service B
   ↓
Service C
```

When investigating an escalation path, understand which component actually executes with elevated privileges.

---

## 22. Service Startup Types

Services may have different startup modes.

Examples:

```text id="f8m5s1"
Boot
System
Auto
Demand
Disabled
```

For escalation analysis, ask:

```text id="h3x8j0"
When does the service execute?
Who starts it?
Can the current user trigger it?
Does a restart occur automatically?
```

A vulnerable service that cannot be triggered may require a different validation approach from one that can be restarted by the current user.

---

## 23. Process vs Service Investigation

Keep the distinction clear:

```text id="1m8h8e"
Process
   ↓
Something currently running

Service
   ↓
A Windows-managed execution mechanism
```

A service often creates or controls a process, but the two concepts should not be treated as identical.

---

## 24. Build a Process Map

For interesting processes:

```text id="6q8t3s"
PROCESS MAP
-----------

Process:
PID:
Owner:
Executable:
Command Line:
Parent PID:
Parent Process:
Integrity Level:
Interesting Files:
Interesting DLLs:
Permissions:
Potential Influence:
```

---

## 25. Build a Service Map

For interesting services:

```text id="w5m7o0"
SERVICE MAP
-----------

Service:
Display Name:
State:
Start Type:
Start Account:
Binary Path:
Dependencies:

Executable Permissions:
Directory Permissions:
Service Permissions:
Registry Configuration:

Potential Writable Resource:
Potential Privilege Boundary:
Validation Required:
```

---

## 26. Process & Service Decision Tree

```text id="z5z3l6"
               Interesting Process/Service
                          │
                          ▼
                 Who runs it?
                          │
                          ▼
               Is the context privileged?
                    /           \
                  No             Yes
                  │               │
                  ▼               ▼
             Lower priority   Examine execution
                                  chain
                                     │
                                     ▼
                            What does it execute?
                                     │
                          ┌──────────┼──────────┐
                          │          │          │
                          ▼          ▼          ▼
                       EXE        DLLs       Config
                          │          │          │
                          └──────────┼──────────┘
                                     ▼
                           Can current user modify
                           or influence the resource?
                                  /       \
                                No         Yes
                                │           │
                                ▼           ▼
                         Record / move   Validate
```

---

## 27. Common Service Findings

Potential findings may include:

* Writable service executable.
* Writable service directory.
* Weak service configuration permissions.
* Unquoted service path.
* Writable DLL dependency.
* Insecure service registry configuration.
* Service running under an unnecessarily privileged account.
* Unsafe executable search behavior.

Each finding must be validated against the actual execution path.

---

## 28. False Positives

Common examples:

```text
SYSTEM service
    ≠
Vulnerable service

Writable file
    ≠
Privilege escalation

Unquoted path
    ≠
Automatic exploitation

Interesting DLL
    ≠
DLL hijacking

Administrative process
    ≠
Accessible process
```

Always establish the complete chain.

---

## 29. Processes & Services Checklist

```text id="w2z6w7"
[ ] Processes enumerated
[ ] Process ownership investigated
[ ] High-privilege processes identified
[ ] Interesting command lines reviewed
[ ] Process paths identified
[ ] Parent-child relationships reviewed
[ ] Services enumerated
[ ] Service accounts identified
[ ] Service configurations inspected
[ ] Service binary paths identified
[ ] Executable permissions checked
[ ] Directory permissions checked
[ ] Parent directories checked
[ ] Service permissions considered
[ ] Service security descriptors reviewed where required
[ ] Unquoted paths investigated
[ ] DLL dependencies considered
[ ] Service registry configuration identified
[ ] Service dependencies reviewed
[ ] Startup behavior understood
[ ] Process maps created
[ ] Service maps created
[ ] Potential escalation paths documented
[ ] False positives eliminated
```

---

## 30. Decision Point

At the end of this stage:

```text id="6g2l7j"
                 Process / Service
                        │
                        ▼
                 Privileged Context?
                    /         \
                  No           Yes
                  │             │
                  ▼             ▼
               Record      Execution Chain
                                │
                ┌───────────────┼───────────────┐
                │               │               │
                ▼               ▼               ▼
             Binary           DLLs           Config
                │               │               │
                └───────────────┼───────────────┘
                                ▼
                         Writable / Controllable?
                              /       \
                            No         Yes
                            │           │
                            ▼           ▼
                       Continue      Validate
                      Enumeration     Path
```

If a service or process produces a strong lead, document it and validate it systematically rather than immediately modifying the target.

---

## Next Step

Proceed to:

```text
07-Scheduled-Tasks/
```

The next stage focuses on another Windows execution mechanism:

> **Which scheduled tasks run automatically, under which security context, what do they execute, and can a lower-privileged user influence the task or anything it executes?**
