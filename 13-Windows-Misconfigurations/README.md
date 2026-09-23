# Windows Misconfigurations

Windows privilege escalation frequently results from security boundaries that were configured incorrectly rather than from a single software vulnerability.

This stage brings together findings from the previous enumeration stages and focuses on common Windows misconfiguration patterns.

The objective is to identify relationships such as:

```text id="5qj4y7"
Unprivileged User
      ↓
Weak Configuration
      ↓
Privileged Resource
      ↓
Control / Influence
      ↓
Privilege Boundary
```

A misconfiguration should be treated as a **lead** until its security impact has been established.

---

## 1. Objective

Identify and analyze Windows misconfigurations involving:

* Services
* Service binaries
* Service directories
* Service permissions
* Scheduled tasks
* Scheduled task resources
* Filesystem permissions
* Registry permissions
* Startup locations
* Privileged applications
* DLL/plugin loading
* PATH/search-order behavior
* Installer configuration
* Token privileges
* Credential exposure
* Named resources
* Network-facing privileged services
* Weak security descriptors
* Administrative group membership

The goal is to answer:

> **Can the current user influence a privileged operation because of a Windows configuration weakness?**

---

## 2. Misconfiguration Mindset

Do not memorize individual exploit techniques first.

Instead identify four components:

```text id="6e8s4s"
1. Attacker-Controlled Resource
2. Privileged Consumer
3. Mechanism Connecting Them
4. Resulting Privilege Boundary
```

Example:

```text id="b0q4jh"
User-writable service directory
        ↓
SYSTEM service
        ↓
Service loads executable from directory
        ↓
User-controlled code executes as SYSTEM
```

Without the privileged consumer, the writable directory may be harmless.

Without the writable resource, the privileged service may also be secure.

The relationship creates the finding.

---

## 3. Misconfiguration Categories

Organize findings into these categories:

```text id="1i0sxn"
Services
Scheduled Tasks
Filesystem
Registry
Applications
Credentials
Tokens / Privileges
Startup Mechanisms
Installers
Network Services
Security Descriptors
Group Membership
```

Avoid duplicating the same finding across multiple categories.

Record the underlying root cause and reference the related enumeration stages.

---

# 4. Service Misconfigurations

Services are one of the most important Windows privilege-escalation areas.

Review:

```cmd id="t2h3pp"
sc query state= all
```

Then inspect relevant services:

```cmd id="1z8hrv"
sc qc <service>
```

PowerShell:

```powershell id="9dyw0u"
Get-CimInstance Win32_Service |
Select-Object Name,DisplayName,State,StartName,PathName
```

---

## 4.1 Writable Service Binary

Check the executable:

```cmd id="gq0rka"
icacls "C:\Path\service.exe"
```

Also inspect its parent directory:

```cmd id="6m0fwm"
icacls "C:\Path\To"
```

Reasoning:

```text id="g2m5jv"
Service runs as SYSTEM
        ↓
Binary or relevant directory is user-writable
        ↓
Current user can influence executable
        ↓
Service executes it
```

The service account must be established before treating this as a privilege-escalation candidate.

---

## 4.2 Weak Service Configuration Permissions

A service may have weak permissions even when its executable is protected.

Inspect the service security descriptor:

```cmd id="r8bq3k"
sc sdshow <service>
```

The objective is to determine whether an unprivileged user can perform security-sensitive service configuration operations.

Do not interpret a raw security descriptor without understanding:

* Principal
* Permission
* Service
* Current user/group membership
* Resulting control

A service being visible is not equivalent to being modifiable.

---

## 4.3 Unquoted Service Paths

Inspect:

```cmd id="j6l9qv"
sc qc <service>
```

Look at:

```text id="4m2b0y"
BINARY_PATH_NAME
```

An unquoted path containing spaces can create ambiguity in executable resolution.

Conceptually:

```text id="1q49n4"
C:\Program Files\Example App\service.exe
```

If the executable path is improperly quoted, Windows may resolve candidate executable paths in a particular order.

However:

> An unquoted path alone does not establish exploitation.

Validate:

1. Exact service path
2. Spaces in the path
3. Whether an earlier candidate path exists
4. Whether the relevant location is writable
5. Service execution account
6. Service start/restart conditions

---

# 5. Scheduled Task Misconfigurations

Review scheduled tasks:

```cmd id="c7a3e2"
schtasks /query /fo LIST /v
```

PowerShell:

```powershell id="e2k5p9"
Get-ScheduledTask
```

Investigate:

* Run-as account
* Executable
* Script
* Arguments
* Working directory
* Trigger
* Task permissions
* Resource permissions

---

## 5.1 Writable Task Executable

Reasoning:

```text id="6xg0lo"
Privileged scheduled task
        ↓
Task executes file
        ↓
Current user can modify file
        ↓
Task runs under privileged account
```

Check:

```cmd id="8wq1m8"
icacls "C:\Path\To\Task.exe"
```

The task must actually execute the resource under the privileged context.

---

## 5.2 Writable Script

A task may execute:

```text id="q4j6t8"
.ps1
.bat
.cmd
.vbs
Other scripts
```

Check:

```cmd id="a3j3l8"
icacls "C:\Path\To\script.ps1"
```

Then determine:

* Who executes the task?
* When does it run?
* Can the current user modify the script?
* Is execution actually performed?
* Does the script perform privileged actions?

---

# 6. Filesystem Misconfigurations

Filesystem permissions should always be analyzed in relation to execution.

Important locations include:

```text id="cvxj2a"
C:\Program Files\
C:\Program Files (x86)\
C:\ProgramData\
C:\Windows\
Application directories
Service directories
Scheduled task resources
Temporary directories
```

Check:

```cmd id="yt5p6v"
icacls "C:\Path"
```

---

## 6.1 Writable Executable

Potential pattern:

```text id="f2r5xw"
Privileged process
        ↓
Executable
        ↓
Current user can modify it
```

Determine:

* Which account runs the process
* When the executable is launched
* Whether the executable is replaced or modified
* Whether other protections prevent modification

---

## 6.2 Writable Parent Directory

A protected executable may still be vulnerable if an attacker can replace, rename, or otherwise manipulate files through a writable parent directory.

Therefore inspect:

```text id="6tw0j7"
Executable
   ↓
Parent directory
   ↓
Higher-level directories
```

Do not stop at the executable's ACL.

---

## 6.3 Delete/Rename Permissions

Write access is not the only relevant permission.

An attacker may have sufficient access to:

* Delete a file
* Rename a file
* Create a replacement
* Modify directory contents

Therefore analyze the effective permissions rather than searching only for the letter `W`.

---

# 7. Registry Misconfigurations

Registry permissions can create privilege-escalation paths when privileged processes consume user-controlled registry values.

Inspect relevant keys:

```cmd id="nqjq07"
reg query HKLM\SOFTWARE
```

Service configuration:

```cmd id="f3w2zy"
reg query HKLM\SYSTEM\CurrentControlSet\Services
```

Review permissions with:

```cmd id="ehk5jr"
icacls "C:\Windows\System32\config"
```

For registry-specific permission analysis, use appropriate registry security tools or PowerShell rather than assuming filesystem ACL output represents registry ACLs.

---

## 7.1 Service Registry Configuration

Important service values include:

```text id="ps2t6s"
ImagePath
ObjectName
Start
Type
DependOnService
```

The relevant pattern is:

```text id="tdzq0m"
Privileged Service
        ↓
Registry Configuration
        ↓
Current User Can Modify Relevant Value
        ↓
Service Consumes Value
        ↓
Privilege Boundary
```

A registry value being writable is not enough.

The privileged process must actually use the modified value.

---

# 8. Startup Misconfigurations

Windows startup mechanisms may execute applications or scripts automatically.

Relevant locations include:

```text id="bhj20k"
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

Query:

```cmd id="u0s0r1"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

```cmd id="5y4nve"
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

The key questions are:

```text id="qv0cst"
Who reads the value?
        ↓
Under which account?
        ↓
What executable/resource is launched?
        ↓
Can the current user modify it?
```

A user-controlled startup entry executing only within the same user's session is generally not a privilege-escalation path.

---

# 9. AlwaysInstallElevated

Windows Installer policy can create a security boundary issue when both relevant policy settings are enabled.

Check:

```cmd id="7xv8a1"
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
```

```cmd id="n7u1ql"
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

Pay attention to:

```text id="y3q5k6"
AlwaysInstallElevated
```

The important condition is not simply that one registry value exists.

Determine whether the relevant policy configuration is enabled in the required scopes and whether it applies to the current environment.

Treat this as a configuration finding requiring careful validation.

---

# 10. DLL and Search-Order Misconfigurations

Privileged applications may load DLLs or other components according to configured search behavior.

Potential pattern:

```text id="b5m9p6"
Privileged Application
        ↓
Loads DLL / Component
        ↓
Searches User-Writable Location
        ↓
Current User Controls Component
```

Investigate:

* Application directory
* Configured DLL directories
* Plugin locations
* PATH
* Application-specific search behavior
* File permissions

Do not assume that a writable directory containing a DLL is exploitable.

The application must actually load the component from that location.

---

# 11. PATH Misconfigurations

Review:

```cmd id="c0s6td"
echo %PATH%
```

PowerShell:

```powershell id="bq7m5c"
$env:Path
```

Identify directories that are:

* User-writable
* Used by privileged processes
* Relevant to executable resolution
* Positioned before trusted directories

The important relationship is:

```text id="r5u9x1"
Privileged Process
        ↓
Searches PATH
        ↓
Writable Directory
        ↓
Required Executable Not Found Earlier
        ↓
User-Controlled Resource
```

A writable PATH directory by itself is not enough.

---

# 12. Token Privilege Misconfigurations

Review:

```cmd id="3y3w3d"
whoami /priv
```

Pay particular attention to powerful privileges such as:

```text id="r3x4i8"
SeBackupPrivilege
SeRestorePrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeAssignPrimaryTokenPrivilege
SeTakeOwnershipPrivilege
SeLoadDriverPrivilege
```

The presence of a privilege is not automatically an exploitable condition.

Determine:

```text id="e4n5gz"
Is the privilege enabled?
        ↓
What resource can it influence?
        ↓
What protections apply?
        ↓
Can it cross the current privilege boundary?
```

Keep privilege enumeration connected to the token analysis from `05-Privileges-and-Access-Tokens/`.

---

# 13. Weak Group Membership

Review local groups:

```cmd id="5n9y0j"
net localgroup
```

Administrators:

```cmd id="a2n0ib"
net localgroup Administrators
```

Potentially interesting groups may include:

```text id="lqg7b7"
Backup Operators
Server Operators
Print Operators
Remote Management Users
Network Configuration Operators
Remote Desktop Users
```

Group membership must be analyzed according to the actual permissions and capabilities provided by that group on the specific system.

Do not classify membership alone as proof of privilege escalation.

---

# 14. Weak Security Descriptors

Windows uses security descriptors to control access to:

```text id="f1j3k5"
Files
Directories
Services
Registry keys
Processes
Named pipes
Objects
Shares
Scheduled tasks
```

A weak descriptor can become significant when:

```text id="1n4q6p"
Current User
      ↓
Has unexpected control permission
      ↓
Over privileged resource
```

Examples of security-sensitive permissions include the ability to:

* Modify
* Write
* Delete
* Change configuration
* Change ownership
* Change permissions
* Start/stop a service

Always identify the exact permission and the object it applies to.

---

# 15. Named Pipes and IPC

Windows applications communicate through mechanisms such as:

```text id="p2z3j7"
Named pipes
RPC
COM
ALPC
Other IPC mechanisms
```

Named pipes may be particularly relevant when a privileged service exposes an IPC interface.

The investigation should determine:

```text id="9w3j3p"
Who creates the object?
        ↓
Who can connect?
        ↓
What operations are available?
        ↓
Which account performs those operations?
        ↓
Can the interaction cross a privilege boundary?
```

Do not treat the mere presence of a named pipe as a vulnerability.

---

# 16. Credential-Related Misconfigurations

Use findings from:

```text
10-Credentials-and-Secrets/
```

Potential relationships include:

```text id="o7v7gj"
Credential Exposure
        ↓
Privileged Account
        ↓
Accessible Authentication Service
        ↓
Additional Privileges
```

Examples may involve:

* Service credentials
* Application configuration
* Scheduled task credentials
* Stored credentials
* Connection strings
* API tokens

Always establish validity and privilege impact before reporting.

---

# 17. Network-Exposed Misconfigurations

Combine this stage with:

```text
12-Network-Enumeration/
```

Example:

```text id="9p7s2d"
Privileged Service
        ↓
Listening Network Port
        ↓
Weak Authentication / Authorization
        ↓
Current User Can Interact
        ↓
Privilege Boundary
```

Network exposure and local privilege escalation should be analyzed together when the same application creates both conditions.

---

# 18. Application Misconfigurations

Use findings from:

```text
11-Applications-and-Installed-Software/
```

Look for:

* Privileged applications
* Writable application directories
* Writable configuration
* Insecure plugins
* Weak update mechanisms
* Hard-coded credentials
* Insecure service integration
* User-controlled temporary files
* Privileged application search paths

The application itself may be secure while its deployment configuration is not.

---

# 19. Misconfiguration Correlation

The strongest findings often require multiple observations.

Example:

```text id="4f5l0d"
Finding A:
Directory is writable
        +
Finding B:
SYSTEM service uses directory
        +
Finding C:
Service loads a user-controlled resource
        =
Privilege-Escalation Candidate
```

Another example:

```text id="4y9b4w"
Finding A:
Credential discovered
        +
Finding B:
Credential belongs to privileged account
        +
Finding C:
Authentication service is accessible
        =
Privilege-Escalation Candidate
```

This is why the repository is structured as a workflow rather than a collection of isolated commands.

---

# 20. Finding Validation

Before calling something exploitable, verify:

### 1. Access

Can the current user actually reach the resource?

### 2. Control

Can the user modify, replace, configure, or influence it?

### 3. Execution

Will a privileged process consume the controlled resource?

### 4. Privilege

Under which account does the operation execute?

### 5. Conditions

Are all required conditions present?

### 6. Impact

Does the result actually cross the privilege boundary?

---

# 21. Validation Model

Use:

```text id="qdbq9x"
Observation
     ↓
Hypothesis
     ↓
Required Conditions
     ↓
Permission Verification
     ↓
Execution Context Verification
     ↓
Minimal Authorized Validation
     ↓
Evidence
     ↓
Impact
```

Example:

```text id="5c7x8x"
Observation:
User-writable service directory

Hypothesis:
Service may load a user-controlled executable

Conditions:
Service runs as SYSTEM
Executable path is within writable directory
Service can be restarted or triggered
No additional protection prevents replacement

Validation:
Authorized lab testing

Result:
Determine whether SYSTEM execution occurs
```

---

# 22. Avoiding False Positives

Before reporting a misconfiguration, ask:

```text id="t4j3g1"
Is the resource actually writable?
Is the privileged consumer actually present?
Does the consumer actually use the resource?
Does it execute/load/read the resource?
Is the current user able to trigger the operation?
Are required conditions satisfied?
Does the result increase privileges?
```

If any critical condition is missing, classify the item as a lead rather than a confirmed finding.

---

# 23. Misconfiguration Matrix

Maintain a working matrix:

| Area        | Weakness            | Privileged Consumer    | User Control | Validated? | Impact |
| ----------- | ------------------- | ---------------------- | ------------ | ---------- | ------ |
| Service     | Writable binary     | SYSTEM service         | Yes/No       | Yes/No     | TBD    |
| Task        | Writable script     | SYSTEM task            | Yes/No       | Yes/No     | TBD    |
| Filesystem  | Writable executable | Privileged process     | Yes/No       | Yes/No     | TBD    |
| Registry    | Writable value      | SYSTEM service         | Yes/No       | Yes/No     | TBD    |
| Application | Weak config         | Privileged application | Yes/No       | Yes/No     | TBD    |
| Credential  | Exposed secret      | Privileged account     | Yes/No       | Yes/No     | TBD    |
| Token       | Powerful privilege  | Current token          | Yes/No       | Yes/No     | TBD    |

This prevents isolated observations from being mistaken for confirmed attack paths.

---

# 24. Common Misconfiguration Checklist

### Services

* [ ] Service binaries checked
* [ ] Service directories checked
* [ ] Service permissions checked
* [ ] Service accounts identified
* [ ] Service paths analyzed
* [ ] Unquoted paths considered

### Scheduled Tasks

* [ ] Task principals identified
* [ ] Executables checked
* [ ] Scripts checked
* [ ] Task resources checked
* [ ] Task permissions considered

### Filesystem

* [ ] Privileged executables checked
* [ ] Parent directories checked
* [ ] Application directories checked
* [ ] ProgramData checked
* [ ] Replacement/delete permissions considered

### Registry

* [ ] Service registry configuration checked
* [ ] Startup locations checked
* [ ] Relevant application keys checked
* [ ] Installer policies checked
* [ ] Registry permissions analyzed

### Applications

* [ ] Privileged applications identified
* [ ] Configurations checked
* [ ] Plugins/DLLs checked
* [ ] Update mechanisms checked
* [ ] Search paths considered

### Tokens

* [ ] Privileges reviewed
* [ ] Enabled privileges identified
* [ ] Integrity level understood
* [ ] Token context understood

### Accounts / Groups

* [ ] Administrators membership checked
* [ ] Special groups checked
* [ ] Service accounts mapped
* [ ] Domain context understood

### Network

* [ ] Privileged network services identified
* [ ] Listening ports mapped
* [ ] Firewall context checked
* [ ] SMB shares reviewed
* [ ] Remote-management services considered

### Validation

* [ ] Access confirmed
* [ ] Control confirmed
* [ ] Privileged consumer confirmed
* [ ] Trigger/execution condition confirmed
* [ ] Impact established
* [ ] False positives eliminated

---

# 25. What This Stage Should Produce

By the end of this stage, raw enumeration should have been converted into a structured set of candidates:

```text id="kwl4q1"
Raw Enumeration
        ↓
Observed Weaknesses
        ↓
Correlated Misconfigurations
        ↓
Privilege-Escalation Candidates
        ↓
Required Conditions
        ↓
Validated Findings
```

The most important skill at this stage is **correlation**.

A writable file, privileged service, exposed credential, or unusual registry value is only an observation until you establish how it crosses the Windows security boundary.

---

## Next Step

Continue to:

```text id="9xq8qv"
14-Validation-and-Exploitation/
```

The next stage will turn validated candidates into a controlled testing workflow: confirming prerequisites, selecting the least invasive validation method, documenting evidence, and performing exploitation only when explicitly authorized.
