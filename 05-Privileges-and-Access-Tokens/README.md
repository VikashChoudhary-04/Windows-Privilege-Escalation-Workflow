# Privileges & Access Tokens

Windows uses security tokens to determine what a process or thread is allowed to do.

A token contains security information associated with a security principal, including:

* User SID.
* Group SIDs.
* Privileges.
* Integrity level.
* Token type.
* Other security attributes.

Understanding the current token is essential for Windows privilege escalation because a privilege may provide capabilities that are not obvious from ordinary group membership.

The objective of this stage is to answer:

> **What security token am I operating under, what privileges does it contain, which privileges are enabled, and can any of them cross a privilege boundary?**

---

## 1. Token-Based Security Model

A simplified model is:

```text
User Account
     ↓
Authentication
     ↓
Access Token
     ↓
 ┌───┼───────────────┐
 │   │               │
 ▼   ▼               ▼
SID Groups      Privileges
        │
        ▼
Integrity Level
        │
        ▼
Process / Thread
        │
        ▼
Resource Access
```

The token is therefore more important than the username alone.

---

## 2. Enumerate Current Privileges

Start with:

```cmd
whoami /priv
```

Example:

```text id="b5x7wv"
Privilege Name                Description
============================= ==========================
SeChangeNotifyPrivilege       Bypass traverse checking
SeIncreaseWorkingSetPrivilege Increase a process working set
```

Record:

```text id="x1ts5s"
Privilege:
State:
Description:
```

---

## 3. Understand Privilege States

A privilege may appear with different states.

Common states include:

```text id="z8i8ab"
Enabled
Disabled
```

Do not treat every listed privilege as immediately usable.

For each interesting privilege, determine:

```text id="krcg44"
Is it present?
Is it enabled?
Can it be enabled?
What operation does it authorize?
Does that operation affect a higher-privileged resource?
```

This distinction is critical.

---

## 4. Common Security-Relevant Privileges

Some privileges deserve additional investigation when present in an unexpected context.

Examples include:

```text id="d0l0fs"
SeBackupPrivilege
SeRestorePrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeAssignPrimaryTokenPrivilege
SeTakeOwnershipPrivilege
SeLoadDriverPrivilege
SeCreateTokenPrivilege
SeTcbPrivilege
```

This is not an automatic exploitation list.

The security significance depends on:

* Windows version.
* Privilege state.
* Token context.
* Process context.
* Required conditions.
* Resource permissions.
* Security controls.

---

## 5. SeBackupPrivilege

`SeBackupPrivilege` is associated with the ability to bypass certain access checks when performing backup operations.

When present, investigate:

```text id="j1gq76"
Who has the privilege?
Is it enabled?
What protected resources are accessible through backup semantics?
Can it affect a security boundary?
What validation is permitted by the assessment?
```

Do not assume that possession of the privilege automatically provides unrestricted access to every protected resource.

---

## 6. SeRestorePrivilege

`SeRestorePrivilege` is associated with restoring files and directories and can affect how certain access checks are performed.

If present, investigate:

```text id="7f6gq8"
Privilege state
    ↓
Accessible resources
    ↓
Required operation
    ↓
Security boundary
    ↓
Potential escalation path
```

The exact impact depends on the resource and Windows security configuration.

---

## 7. SeDebugPrivilege

`SeDebugPrivilege` is associated with debugging processes that the caller would otherwise not have normal access to.

Check:

```cmd id="s8p1h6"
whoami /priv
```

If present, determine:

* Whether it is enabled.
* Which processes are accessible.
* What security context those processes use.
* Whether the current assessment permits process interaction.

Do not interact with unrelated processes simply because the privilege is present.

---

## 8. SeImpersonatePrivilege

`SeImpersonatePrivilege` allows a process to impersonate a client under certain conditions.

It can become particularly important when a process running with this privilege interacts with a more privileged authentication context.

When encountered, investigate:

```text id="qg13v7"
Who owns the token?
       ↓
Is SeImpersonatePrivilege present?
       ↓
Is it enabled?
       ↓
What privileged authentication paths exist?
       ↓
Are the required conditions present?
       ↓
Can the behavior be safely validated?
```

The presence of the privilege alone does not prove an exploitable escalation path.

---

## 9. SeAssignPrimaryTokenPrivilege

This privilege can allow a process to replace the primary token associated with a process under appropriate conditions.

When encountered, investigate:

```text id="z8mxv4"
Current process context
        ↓
Privilege state
        ↓
Available token
        ↓
Required permissions
        ↓
Resulting security context
```

Validation must account for the exact Windows configuration.

---

## 10. SeTakeOwnershipPrivilege

This privilege can allow the holder to take ownership of certain securable objects.

The important distinction is:

```text id="h4l3d1"
Ownership
    ≠
Full access
```

Taking ownership does not automatically grant every permission on an object.

After identifying this privilege, investigate:

* Which object is relevant.
* Current owner.
* Existing ACL.
* Required access.
* Whether ownership can be changed under the current token.
* Whether changing ownership is within scope.

---

## 11. SeLoadDriverPrivilege

This privilege is associated with loading drivers.

Drivers operate at a highly privileged level, so this privilege deserves careful treatment.

If present:

```text id="4aqj3p"
Identify privilege
      ↓
Determine state
      ↓
Determine driver-related permissions
      ↓
Review authorized validation options
```

Do not load arbitrary drivers during routine enumeration.

---

## 12. Integrity Levels

Windows Mandatory Integrity Control assigns integrity levels to security tokens.

Common levels include:

```text id="g6yyj4"
Low
Medium
High
System
```

Inspect the current token:

```cmd id="9x6mwp"
whoami /groups
```

Look for:

```text id="qk6z7t"
Mandatory Label\Low Mandatory Level
Mandatory Label\Medium Mandatory Level
Mandatory Label\High Mandatory Level
Mandatory Label\System Mandatory Level
```

Integrity level should be interpreted alongside:

* User SID.
* Groups.
* Privileges.
* UAC state.
* Process context.

---

## 13. Understanding UAC and Tokens

On systems with User Account Control, administrative users may operate with different token contexts.

A simplified model:

```text
Administrator Account
        │
        ▼
UAC
   ┌────┴────┐
   ▼         ▼
Filtered    Elevated
 Token       Token
   │           │
   ▼           ▼
Medium       High
Integrity   Integrity
```

Therefore:

```text
Member of Administrators
        ≠
Currently operating with unrestricted administrative token
```

This is why both:

```cmd id="b4h1c4"
net localgroup Administrators
```

and:

```cmd id="m8c8aj"
whoami /groups
```

matter.

---

## 14. Token Types

Windows tokens can have different types.

Conceptually:

```text id="b9c8f4"
Primary Token
     │
     └── Associated with a process

Impersonation Token
     │
     └── Allows a thread to act in another security context
```

Token type becomes particularly important when investigating:

* Service processes.
* Authentication mechanisms.
* Impersonation.
* Remote management.
* Privileged process interactions.

---

## 15. Process vs Thread Security Context

A process normally operates under a primary token.

A thread can sometimes use an impersonation token.

Conceptually:

```text id="9ksg7a"
Process
   │
   └── Primary Token
          │
          ▼
       Process
          │
          ├── Thread 1
          │
          ├── Thread 2
          │
          └── Thread 3
                 │
                 └── Possible impersonation context
```

This distinction becomes important when investigating Windows services and impersonation-related privilege escalation.

---

## 16. Security Identifiers

Review the current user SID:

```cmd id="xqvjxj"
whoami /user
```

Review group SIDs:

```cmd id="u7g9j5"
whoami /groups
```

SIDs become useful when correlating:

```text id="y3i8fj"
User
 ↓
Token
 ↓
SID
 ↓
ACL
 ↓
Resource Access
```

For example, an ACL may grant permissions to a SID rather than displaying the friendly account name.

---

## 17. Privilege-to-Resource Reasoning

Do not investigate privileges in isolation.

Use:

```text id="13fj52"
Privilege
    ↓
Capability
    ↓
Resource
    ↓
Required Access
    ↓
Security Boundary
    ↓
Validation
```

Example:

```text id="b1cqkc"
SeTakeOwnershipPrivilege
        ↓
Can potentially affect ownership
        ↓
Identify security-sensitive object
        ↓
Inspect its ACL
        ↓
Determine whether ownership enables required access
        ↓
Validate within scope
```

This is the reasoning pattern used throughout the repository.

---

## 18. Identify Interesting Privileges

Create a table during an assessment:

| Privilege                  | State            | Why Interesting          | Further Investigation     |
| -------------------------- | ---------------- | ------------------------ | ------------------------- |
| `SeBackupPrivilege`        | Enabled/Disabled | Backup-related access    | Protected resources       |
| `SeRestorePrivilege`       | Enabled/Disabled | Restore-related access   | Resource permissions      |
| `SeDebugPrivilege`         | Enabled/Disabled | Process debugging        | Process security contexts |
| `SeImpersonatePrivilege`   | Enabled/Disabled | Impersonation capability | Authentication paths      |
| `SeTakeOwnershipPrivilege` | Enabled/Disabled | Ownership changes        | Object ACLs               |
| `SeLoadDriverPrivilege`    | Enabled/Disabled | Driver loading           | Driver security           |

The table is a **triage aid**, not a list of guaranteed exploits.

---

## 19. Do Not Confuse Privileges With Permissions

Windows security has several related but different concepts:

```text id="3v1w9k"
User
 ↓
Group Membership
 ↓
Token Privileges
 ↓
Object Permissions / ACLs
 ↓
Integrity Level
 ↓
Effective Access
```

For example:

```text id="tqjz2h"
Being an Administrator
        ≠
Having every privilege enabled
        ≠
Having unrestricted access to every object
```

This distinction is essential when validating escalation paths.

---

## 20. Token Enumeration Checklist

```text id="t5yd8k"
[ ] Current token inspected
[ ] User SID identified
[ ] Group SIDs identified
[ ] Group states reviewed
[ ] Integrity level identified
[ ] Privileges enumerated
[ ] Privilege states reviewed
[ ] Interesting privileges documented
[ ] UAC context understood
[ ] Token type considered
[ ] Process/thread context considered
[ ] Potential impersonation context identified
[ ] Interesting privilege-to-resource relationships documented
```

---

## 21. Build the Token Profile

Maintain a concise token profile:

```text id="u7e7q4"
TOKEN PROFILE
-------------

User:
User SID:

Integrity Level:

Token Groups:

Interesting Groups:

Privileges:

Enabled Privileges:

Disabled Privileges:

UAC Context:

Token Type:

Potentially Relevant Privileges:

Potential Privilege Paths:
```

---

## 22. Decision Point

At the end of this stage:

```text id="7kq0ip"
                 Token Analysis
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
   Interesting     Interesting    No obvious
    Privilege        Group           Lead
        │              │              │
        ▼              ▼              ▼
   Investigate     Investigate    Continue
    capability      access       enumeration
        │              │              │
        └──────────────┼──────────────┘
                       ▼
                Identify Path
```

If a privilege looks interesting, do not immediately exploit it.

First establish:

1. What the privilege allows.
2. Whether it is enabled.
3. What resource could be affected.
4. Whether the current token can perform the required operation.
5. Whether the conditions for escalation exist.

---

## Next Step

Proceed to:

```text id="p3b8mz"
06-Processes-and-Services/
```

The next stage investigates one of the richest Windows privilege-escalation areas:

> **Which processes and services are running, under which accounts, from which executable paths, and with what permissions?**

This is where the workflow begins connecting **privileged execution + writable resources + service/process behavior** into concrete escalation hypotheses.
