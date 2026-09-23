# Initial Access Context

Before beginning detailed Windows privilege escalation enumeration, establish the security context from which the investigation starts.

The objective is to answer:

> **Who am I, what access do I have, how did I obtain it, and what security boundary am I currently below?**

This information determines how the rest of the privilege escalation workflow should proceed.

---

## 1. Identify the Current User

Start by identifying the account associated with the current session.

### Command

```cmd
whoami
```

Example:

```text
C:\> whoami
winlab\student
```

This establishes the current security principal.

For additional account information:

```cmd
whoami /user
```

This displays the user's SID.

```cmd
whoami /groups
```

This displays the groups associated with the current security token.

```cmd
whoami /priv
```

This displays privileges assigned to the current token.

---

## 2. Record the Current Security Context

At this stage, record:

```text
Username:
Domain:
SID:
Groups:
Privileges:
Integrity Level:
```

A useful initial workflow is:

```text
whoami
    ↓
whoami /user
    ↓
whoami /groups
    ↓
whoami /priv
```

Do not immediately assume that membership in a group or possession of a privilege means it can be used for escalation.

Each finding needs to be interpreted in context.

---

## 3. Determine the Hostname

Identify the Windows host.

```cmd
hostname
```

Alternative:

```cmd
echo %COMPUTERNAME%
```

Record the result because host identity becomes important when correlating local and network information later.

---

## 4. Identify the Operating System

Determine the Windows version and system information.

### Basic information

```cmd
ver
```

### Detailed information

```cmd
systeminfo
```

Useful information from `systeminfo` can include:

* OS name
* OS version
* OS build
* System manufacturer
* System model
* System type
* Registered owner
* Installation date
* Boot time
* Hotfix information
* Network configuration

Do not treat an old-looking version or missing update as automatically exploitable.

The information must be correlated with the specific system configuration and applicable security issues.

---

## 5. Determine System Architecture

Identify whether the system is 32-bit or 64-bit.

```cmd
echo %PROCESSOR_ARCHITECTURE%
```

Also inspect:

```cmd
systeminfo
```

Architecture can affect:

* Available binaries
* Process compatibility
* DLL loading
* Exploit compatibility
* Installed software
* PowerShell behavior

---

## 6. Identify the Current Shell

Determine which command environment is currently available.

### Command Prompt

```cmd
echo %ComSpec%
```

### PowerShell

```powershell
$PSVersionTable
```

If PowerShell is available, record its version.

PowerShell version and execution context can affect which enumeration techniques are practical.

---

## 7. Determine How Access Was Obtained

Establish the nature of the current session.

Examples:

```text
Local interactive session
Remote desktop session
Remote shell
Application shell
Service context
Scheduled-task context
Command execution through another service
```

This distinction matters because the same account may behave differently depending on how the session was created.

Record:

```text
Access Type:
Access Method:
Interactive / Non-Interactive:
```

---

## 8. Determine Whether the Account Is Local or Domain-Based

Inspect the account identity:

```cmd
whoami
```

Example:

```text
WINLAB\student
```

or:

```text
CORP\student
```

The naming context can provide an initial indication of whether the account is local or associated with a domain.

Additional information can be gathered with:

```cmd
whoami /upn
```

where applicable.

Do not assume that domain membership automatically means the current account has useful domain privileges.

---

## 9. Examine Group Membership

List the groups associated with the current token:

```cmd
whoami /groups
```

Also consider:

```cmd
net user %USERNAME%
```

Group membership may reveal security-relevant roles.

Examples include:

* Administrators
* Remote Desktop Users
* Backup Operators
* Server Operators
* Print Operators
* Account Operators
* Other privileged or application-specific groups

Group membership should be investigated further rather than treated as an automatic escalation path.

---

## 10. Examine Assigned Privileges

List privileges available to the current token:

```cmd
whoami /priv
```

Pay attention to privileges that may have security implications.

Examples can include:

```text
SeBackupPrivilege
SeRestorePrivilege
SeImpersonatePrivilege
SeAssignPrimaryTokenPrivilege
SeDebugPrivilege
SeTakeOwnershipPrivilege
```

Important:

A privilege appearing in the output does not necessarily mean it is currently usable.

Inspect:

* Whether the privilege is enabled.
* Whether it is disabled.
* Whether the account can enable it.
* Whether the surrounding conditions required for abuse exist.

The objective is to understand the token rather than simply search for interesting privilege names.

---

## 11. Check Integrity Level

Windows integrity levels provide another important part of the security context.

Use:

```cmd
whoami /groups
```

Look for an entry similar to:

```text
Mandatory Label\Medium Mandatory Level
```

Common integrity levels include:

```text
Low
Medium
High
System
```

The integrity level helps describe the trust level associated with the current process token.

It should be considered together with:

* User identity
* Group membership
* Token privileges
* Process context
* UAC configuration

---

## 12. Check Environment Variables

Environment variables can provide useful contextual information.

```cmd
set
```

For selected variables:

```cmd
echo %PATH%
echo %TEMP%
echo %USERPROFILE%
echo %APPDATA%
echo %PROGRAMDATA%
```

Pay particular attention to:

* `PATH`
* User-controlled directories
* Temporary directories
* Application-specific paths
* Unusual custom environment variables

Do not assume that a writable directory in `PATH` automatically creates a privilege escalation vulnerability. Determine which privileged process uses the path and how the executable resolution occurs.

---

## 13. Establish the Initial Baseline

At the end of this stage, you should be able to describe the starting context.

Example:

```text
Host:
    WINLAB

Operating System:
    Windows 11

Architecture:
    64-bit

User:
    winlab\student

Access:
    Interactive command shell

Groups:
    Users
    Remote Desktop Users

Integrity:
    Medium

Interesting Privileges:
    None identified yet

Shell:
    CMD / PowerShell

Domain Context:
    Workgroup / Domain
```

This becomes the baseline for the remainder of the investigation.

---

## 14. Initial Context Decision Point

Use the collected information to decide where to investigate next.

```text
                Initial Context
                       │
          ┌────────────┼────────────┐
          │            │            │
          ▼            ▼            ▼
      Groups       Privileges     System
          │            │            │
          │            │            │
          ▼            ▼            ▼
    Interesting?   Interesting?   What OS?
          │            │            │
          └────────────┼────────────┘
                       ▼
              Continue Enumeration
```

The next stage should not be chosen solely because a particular command produced an interesting-looking result.

The goal is to build a complete understanding of the host.

---

## 15. Initial Access Checklist

```text
[ ] Current username identified
[ ] User SID identified
[ ] Hostname identified
[ ] Operating system identified
[ ] Windows version/build recorded
[ ] System architecture identified
[ ] Current shell identified
[ ] PowerShell version checked where available
[ ] Local/domain context identified
[ ] Current groups enumerated
[ ] Current privileges enumerated
[ ] Integrity level identified
[ ] Environment variables reviewed
[ ] Access method documented
[ ] Initial security context recorded
```

---

## What Comes Next?

Once the initial access context is established, move to:

```text
02-First-5-Minutes/
```

The next stage converts the information gathered here into a **rapid first-pass enumeration routine**.

The goal is to quickly identify obvious leads before performing deeper investigation.
