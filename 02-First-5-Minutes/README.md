# First 5 Minutes

The first few minutes after obtaining access to a Windows system should be used to establish a rapid baseline and identify obvious leads.

This stage is **triage**, not a complete enumeration.

The objective is to quickly answer:

> **What system am I on, what context do I have, what is running, and where should I investigate first?**

Avoid spending too much time investigating a single finding during this stage. Record interesting leads and continue with the baseline.

---

## 1. First-Minute Workflow

A compact first-pass workflow:

```text
Current User
    ↓
Hostname
    ↓
OS & Architecture
    ↓
Groups & Privileges
    ↓
Network
    ↓
Processes
    ↓
Services
    ↓
Scheduled Tasks
    ↓
Interesting Files / Applications
    ↓
Prioritize Leads
```

The exact commands available depend on the shell and permissions.

---

## 2. Confirm Current Context

Start by confirming the session has not changed.

```cmd
whoami
whoami /groups
whoami /priv
hostname
```

Record anything immediately relevant:

```text
User:
Hostname:
Groups:
Privileges:
Integrity Level:
```

If the session is non-interactive, also record how the shell was obtained.

---

## 3. Identify the Operating System

Perform a quick OS check.

```cmd
systeminfo
```

For a faster version:

```cmd
ver
```

Record:

```text
OS:
Version:
Build:
Architecture:
```

The purpose at this stage is identification, not vulnerability matching.

Detailed patch and update analysis will be handled later.

---

## 4. Check Network Configuration

Quickly establish the host's network position.

```cmd
ipconfig /all
```

Then:

```cmd
route print
```

Check active connections:

```cmd
netstat -ano
```

Look for:

* Network interfaces
* IP addresses
* DNS configuration
* Default gateway
* Routes
* Listening ports
* Established connections
* Associated process IDs

Do not immediately treat an open port as a privilege escalation finding.

At this stage, record interesting observations for later investigation.

---

## 5. Check Running Processes

Identify processes running on the system.

```cmd
tasklist
```

For additional details:

```cmd
tasklist /v
```

Useful questions:

```text
Which processes run as SYSTEM?
Which processes run as other privileged accounts?
Which applications are running?
Are security products present?
Are unusual processes running?
Are there processes associated with installed applications?
```

The objective is to identify **interesting processes and their security context**, not simply produce a process list.

---

## 6. Check Windows Services

List services:

```cmd
sc query
```

A more compact view:

```cmd
sc query state= all
```

You can also use:

```cmd
wmic service get Name,DisplayName,State,StartName,PathName
```

where WMIC is available.

Focus on:

```text
Service Name
Display Name
State
Start Account
Executable Path
```

Interesting services should be recorded for deeper investigation in:

```text
06-Processes-and-Services/
```

Do not attempt to modify a service during the triage stage.

---

## 7. Check Scheduled Tasks

List scheduled tasks:

```cmd
schtasks /query
```

For verbose information:

```cmd
schtasks /query /fo LIST /v
```

Look for:

* Tasks running with elevated accounts.
* Unusual task names.
* Custom application tasks.
* Tasks executing scripts.
* Tasks executing binaries from unusual locations.
* Writable task resources.

Interesting tasks should be investigated later in:

```text
07-Scheduled-Tasks/
```

---

## 8. Check Users

List local users:

```cmd
net user
```

Then inspect the current account:

```cmd
net user %USERNAME%
```

If appropriate and authorized:

```cmd
net localgroup
```

The purpose is to identify:

* Local accounts
* Administrative groups
* Service-related accounts
* Unusual accounts
* Account configuration

Do not assume that a username alone indicates privilege.

---

## 9. Check Installed Applications

A quick inventory can reveal software that deserves deeper investigation.

Where supported:

```cmd
wmic product get name,version
```

However, `wmic product` is not a complete inventory mechanism and may be unavailable or unsuitable on modern Windows systems.

Other useful locations include:

```text
C:\Program Files\
C:\Program Files (x86)\
```

PowerShell can also be used for more targeted software enumeration.

At this stage, simply identify potentially relevant applications.

---

## 10. Inspect the PATH

Check the current executable search path:

```cmd
echo %PATH%
```

Look for:

* Unusual directories
* User-writable locations
* Temporary directories
* Application-specific directories
* Missing or unexpected paths

A writable `PATH` entry alone is not sufficient evidence of privilege escalation.

Determine whether a privileged process actually resolves an executable through that path.

---

## 11. Check Common Writable Locations

Quickly identify the current user's temporary and profile locations:

```cmd
echo %TEMP%
echo %TMP%
echo %USERPROFILE%
echo %APPDATA%
echo %PROGRAMDATA%
```

These locations may become relevant when investigating:

* Application behavior
* Scheduled tasks
* Service execution
* Script execution
* Temporary-file handling

Do not modify files simply because they are writable.

---

## 12. Look for Obvious Interesting Files

Perform only lightweight initial checks.

Examples:

```cmd
dir C:\ /a
dir C:\Users
dir "C:\Program Files"
dir "C:\Program Files (x86)"
```

Potentially interesting locations include:

```text
C:\Users\
C:\ProgramData\
C:\Program Files\
C:\Program Files (x86)\
C:\Windows\Temp\
```

Detailed filesystem and permission analysis belongs in:

```text
08-Filesystem-and-Permissions/
```

---

## 13. Build a Lead List

Do not try to fully investigate every interesting result immediately.

Create a short lead list.

Example:

```text
Potential Lead
--------------
[ ] Interesting group membership
[ ] Interesting token privilege
[ ] SYSTEM service
[ ] Unusual service executable
[ ] Writable application directory
[ ] Elevated scheduled task
[ ] Suspicious process
[ ] Interesting listening service
[ ] Unusual installed application
[ ] Potential credential location
```

Each lead should later be validated.

---

## 14. Prioritize Findings

A useful triage model is:

```text
                    Finding
                       │
                       ▼
              Does it cross a
             privilege boundary?
                 /          \
               No            Yes
               │              │
               ▼              ▼
          Record only     Investigate
                              │
                              ▼
                       Is it actually
                          writable /
                           usable?
                         /          \
                       No            Yes
                       │              │
                       ▼              ▼
                  Low priority    Validate
```

This prevents the workflow from becoming a collection of false positives.

---

## 15. What NOT to Do

The first five minutes are not the time to:

* Run every available enumeration script blindly.
* Modify services.
* Modify registry settings.
* Delete files.
* Disable security software.
* Create persistence.
* Change account privileges.
* Dump credentials unnecessarily.
* Exploit every suspicious configuration immediately.

First establish the baseline.

Then investigate.

---

## 16. First 5 Minutes Checklist

```text
[ ] Confirm current user
[ ] Confirm groups
[ ] Confirm privileges
[ ] Confirm hostname
[ ] Identify OS and architecture
[ ] Check network configuration
[ ] Check routes
[ ] Check active connections
[ ] Enumerate running processes
[ ] Enumerate services
[ ] Enumerate scheduled tasks
[ ] Review local users
[ ] Review administrative groups
[ ] Identify installed applications
[ ] Review PATH
[ ] Identify important writable locations
[ ] Record interesting files/directories
[ ] Build a lead list
[ ] Prioritize leads
```

---

## 17. Rapid Enumeration Notes

Keep the output or relevant observations from the first pass.

```text
Target:
Hostname:
IP:
User:
OS:
Architecture:
Groups:
Privileges:
Integrity:
Network:
Interesting Processes:
Interesting Services:
Interesting Tasks:
Interesting Applications:
Interesting Files:
Potential Leads:
```

The notes should be concise enough to allow the investigation to continue without repeatedly running the same commands.

---

## Decision Point

After the first-pass triage, choose the next investigation area based on the evidence.

```text
                       First Pass
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
   User/Token          Services/Tasks      System
        │                  │                  │
        ▼                  ▼                  ▼
   Privilege path      Execution path     Configuration
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ▼
                    Deeper Enumeration
```

If no obvious lead exists, continue systematically rather than guessing.

---

## Next Step

Proceed to:

```text
03-System-Enumeration/
```

This stage performs a deeper examination of the Windows operating system, including version/build information, system configuration, installed updates, environment, security configuration, and other host-level information that can influence privilege escalation.
