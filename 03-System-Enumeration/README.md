# System Enumeration

System enumeration is the process of understanding the Windows host itself before investigating specific privilege escalation paths.

The objective is to establish:

> **What version of Windows is running, how is the system configured, what security controls and updates are present, and what host-level characteristics could affect privilege escalation?**

This stage builds on the rapid triage performed in `02-First-5-Minutes/`.

---

## 1. Enumeration Objectives

System enumeration should establish:

* Windows edition and version.
* OS build.
* System architecture.
* Hostname.
* Domain/workgroup membership.
* System uptime.
* Installation information.
* Installed updates.
* Environment variables.
* System and user paths.
* Security configuration.
* UAC configuration.
* Windows Defender/security-product presence.
* Relevant system configuration.
* Potentially interesting host-level weaknesses.

The goal is not simply to collect information.

The goal is to understand how that information affects the security boundary.

---

## 2. Operating System Information

Start with the basic OS information.

### Version

```cmd
ver
```

### Detailed information

```cmd
systeminfo
```

Useful fields include:

```text
OS Name
OS Version
OS Build
System Type
System Manufacturer
System Model
Registered Owner
Original Install Date
System Boot Time
```

Record the relevant information:

```text
OS:
Edition:
Version:
Build:
Architecture:
Install Date:
Boot Time:
```

---

## 3. Windows Architecture

Confirm the architecture:

```cmd
echo %PROCESSOR_ARCHITECTURE%
```

Also inspect:

```cmd
systeminfo
```

Common values include:

```text
AMD64
x86
ARM64
```

Architecture can affect:

* Available executables.
* DLL compatibility.
* Process architecture.
* Application installation paths.
* Security tooling.
* Exploit compatibility.

---

## 4. Hostname

Confirm the system identity:

```cmd
hostname
```

Alternative:

```cmd
echo %COMPUTERNAME%
```

Record:

```text
Hostname:
```

This becomes important when correlating local information with network and domain information.

---

## 5. Domain or Workgroup Membership

Check domain/workgroup information:

```cmd
systeminfo
```

Look for:

```text
Domain:
```

Another option:

```cmd
wmic computersystem get domain,partofdomain
```

where WMIC is available.

PowerShell:

```powershell
Get-CimInstance Win32_ComputerSystem |
Select-Object Name,Domain,PartOfDomain
```

Determine whether the host is:

```text
Workgroup
    or
Domain-joined
```

Domain membership does not automatically mean that the current user has elevated privileges.

It simply changes the security context and possible attack surface that should be considered later.

---

## 6. System Uptime

Check how long the system has been running.

```cmd
systeminfo
```

Look for:

```text
System Boot Time
```

PowerShell provides another method:

```powershell
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
```

Uptime can provide context when interpreting:

* Running processes.
* Services.
* Scheduled tasks.
* Recent configuration changes.
* Pending updates.

---

## 7. Installed Updates and Hotfixes

Review installed hotfixes:

```cmd
systeminfo
```

or:

```cmd
wmic qfe get HotFixID,InstalledOn,Description
```

where available.

PowerShell:

```powershell
Get-HotFix
```

Record:

```text
Hotfix ID:
Description:
Installation Date:
```

### Important

A missing update should **not** automatically be treated as a privilege escalation vulnerability.

Determine:

1. Which component is affected.
2. Whether the relevant vulnerability applies to the exact OS/build.
3. Whether exploitation requires additional conditions.
4. Whether the vulnerability actually crosses a privilege boundary.
5. Whether the environment permits testing it.

Patch enumeration is therefore an information-gathering step, not an automatic exploit-selection mechanism.

---

## 8. Environment Variables

Review system environment variables:

```cmd
set
```

Useful individual variables:

```cmd
echo %PATH%
echo %PATHEXT%
echo %TEMP%
echo %TMP%
echo %SYSTEMROOT%
echo %WINDIR%
echo %PROGRAMDATA%
echo %PROGRAMFILES%
echo %PROGRAMFILES(X86)%
echo %USERPROFILE%
echo %APPDATA%
```

PowerShell:

```powershell
Get-ChildItem Env:
```

Pay particular attention to:

* `PATH`
* `PATHEXT`
* Temporary directories.
* User-controlled directories.
* Application-specific paths.

Environment variables should always be interpreted in the context of the process using them.

---

## 9. PATH Analysis

Inspect:

```cmd
echo %PATH%
```

Ask:

```text
Which directories are included?
        ↓
Which directories are writable?
        ↓
Which executable is being searched for?
        ↓
Which process performs the lookup?
        ↓
Does that process execute with higher privileges?
```

A writable directory in `PATH` alone is not evidence of privilege escalation.

The complete execution chain must be established.

---

## 10. Windows Directory Structure

Inspect the major system directories.

```cmd
dir C:\ /a
```

Important locations include:

```text
C:\Windows\
C:\Windows\System32\
C:\Windows\SysWOW64\
C:\Program Files\
C:\Program Files (x86)\
C:\ProgramData\
C:\Users\
```

At this stage, the goal is orientation.

Detailed permission analysis will be performed later under:

```text
08-Filesystem-and-Permissions/
```

---

## 11. System Configuration

Windows stores significant configuration information through the registry and system management interfaces.

A basic system configuration query:

```cmd
systeminfo
```

Additional information can be obtained through PowerShell:

```powershell
Get-CimInstance Win32_OperatingSystem
```

For computer information:

```powershell
Get-CimInstance Win32_ComputerSystem
```

For BIOS information:

```powershell
Get-CimInstance Win32_BIOS
```

For processor information:

```powershell
Get-CimInstance Win32_Processor
```

These commands help establish the underlying system environment.

---

## 12. Security Product Discovery

Determine whether security products are present.

PowerShell can query registered antivirus products where the relevant WMI namespace is available:

```powershell
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
```

This may provide information such as:

* Security product name.
* Product status.
* Product instance information.

Also inspect running processes and services for security-related components.

### Important

The purpose is **situational awareness**.

Do not disable, bypass, or tamper with security controls during routine enumeration.

---

## 13. Windows Defender Status

On systems where Defender cmdlets are available:

```powershell
Get-MpComputerStatus
```

Useful information may include:

* Antivirus status.
* Real-time protection status.
* Antispyware status.
* Engine information.
* Signature information.

Security-control configuration can affect what testing techniques are appropriate in an authorized environment.

---

## 14. User Environment

Inspect the current user's environment:

```cmd
echo %USERPROFILE%
echo %HOMEDRIVE%
echo %HOMEPATH%
echo %APPDATA%
echo %LOCALAPPDATA%
echo %TEMP%
```

List the user profile directory:

```cmd
dir "%USERPROFILE%"
```

Potentially relevant locations include:

```text
Desktop
Documents
Downloads
AppData
Local Settings
```

Do not indiscriminately search or copy personal data.

The objective is to identify security-relevant application configuration and execution paths.

---

## 15. System and User PATH Differences

Compare the effective PATH with the underlying system/user configuration where necessary.

PowerShell:

```powershell
[Environment]::GetEnvironmentVariable("Path","Machine")
[Environment]::GetEnvironmentVariable("Path","User")
```

This can help determine whether a path originates from:

```text
Machine-level configuration
        or
User-level configuration
```

A path that is controlled by a lower-privileged user becomes interesting only when a higher-privileged process relies on it.

---

## 16. Check Windows Services at the System Level

Services will receive detailed analysis later, but system enumeration should establish their presence.

```cmd
sc query state= all
```

PowerShell:

```powershell
Get-Service
```

Record potentially relevant information such as:

```text
Service Name
Status
Startup Type
```

Detailed service analysis belongs in:

```text
06-Processes-and-Services/
```

---

## 17. Check Scheduled Task Infrastructure

Perform a basic inventory:

```cmd
schtasks /query
```

The purpose here is to establish whether custom or unusual scheduled tasks exist.

Detailed analysis belongs in:

```text
07-Scheduled-Tasks/
```

---

## 18. System-Level Registry Awareness

The Windows registry contains configuration used by:

* Windows components.
* Services.
* Applications.
* Drivers.
* Startup mechanisms.
* User profiles.
* Security settings.

Do not begin by dumping the entire registry.

Instead, understand that registry investigation will later be targeted toward security-relevant locations.

Registry-specific enumeration belongs in:

```text
09-Registry/
```

---

## 19. Identify Drivers

List installed or active drivers:

```cmd
driverquery
```

For additional information:

```cmd
driverquery /v
```

Drivers operate at a highly privileged level.

However, simply finding an unusual driver does not establish a vulnerability.

For each interesting driver, determine:

```text
What is it?
Who installed it?
Is it currently loaded?
What software uses it?
What permissions/configuration does it have?
Is there a documented security issue?
```

---

## 20. Check System Information Through PowerShell

PowerShell provides structured access to Windows management information.

Examples:

```powershell
Get-CimInstance Win32_OperatingSystem
```

```powershell
Get-CimInstance Win32_ComputerSystem
```

```powershell
Get-CimInstance Win32_LogicalDisk
```

```powershell
Get-CimInstance Win32_Processor
```

```powershell
Get-CimInstance Win32_ComputerSystemProduct
```

Structured output can be easier to process than traditional command output when performing detailed enumeration.

---

## 21. Build the System Profile

At the end of this stage, create a concise system profile.

```text
SYSTEM PROFILE
--------------

Hostname:
OS:
Edition:
Version:
Build:
Architecture:

Domain:
Workgroup:

System Manufacturer:
System Model:

Boot Time:
Uptime:

Installed Updates:

Security Products:

PowerShell Version:

Interesting Environment Variables:

Interesting Drivers:

Interesting Services:

Interesting Scheduled Tasks:

Potential Leads:
```

This profile becomes the system-level baseline for subsequent investigation.

---

## 22. Reasoning Process

Do not treat system enumeration as a checklist where every result is automatically a finding.

Use:

```text
Observation
     ↓
Why is it relevant?
     ↓
Does it affect a privilege boundary?
     ↓
What additional information is required?
     ↓
Can the condition be validated?
     ↓
Is there a legitimate escalation path?
```

Example:

```text
Old Windows Build
       ↓
Potential security issue
       ↓
Identify exact build
       ↓
Identify affected component
       ↓
Determine vulnerability conditions
       ↓
Determine whether local privilege escalation applies
       ↓
Validate in the authorized environment
```

---

## 23. System Enumeration Checklist

```text
[ ] OS identified
[ ] Edition identified
[ ] Version identified
[ ] Build identified
[ ] Architecture identified
[ ] Hostname recorded
[ ] Domain/workgroup identified
[ ] System uptime recorded
[ ] Installed updates reviewed
[ ] Environment variables reviewed
[ ] PATH reviewed
[ ] System directories identified
[ ] User environment reviewed
[ ] Security products identified
[ ] Windows Defender status reviewed where applicable
[ ] Services inventoried
[ ] Scheduled tasks inventoried
[ ] Drivers inventoried
[ ] System configuration reviewed
[ ] Initial system profile created
[ ] Potential leads documented
```

---

## Next Step

Once system-level enumeration is complete, move to:

```text
04-Users-and-Groups/
```

The next stage focuses specifically on **Windows identities, local accounts, groups, memberships, account configuration, and privilege relationships**.

The key question becomes:

> **Who exists on this system, what groups are they associated with, and what access does those relationships provide?**
