# Filesystem & Permissions

Windows uses NTFS permissions and Access Control Lists (ACLs) to control access to files and directories.

Filesystem permissions are important in privilege escalation because a privileged process may execute or load a resource that a lower-privileged user can modify.

The objective of this stage is to answer:

> **What filesystem resources can the current user access or modify, and does any writable resource intersect with a privileged execution path?**

---

## 1. Investigation Model

Use the following model:

```text id="c3v8am"
Resource
   ↓
Owner
   ↓
ACL
   ↓
Current User / Group
   ↓
Effective Permission
   ↓
Who Executes or Uses It?
   ↓
Privilege Context
   ↓
Potential Privilege Boundary
```

A writable file is not automatically a privilege escalation vulnerability.

The resource must be connected to something that operates with greater privileges or otherwise crosses a security boundary.

---

## 2. NTFS Permission Concepts

Windows filesystem access commonly involves:

* Users.
* Groups.
* Security identifiers.
* Owners.
* Access Control Entries.
* Access Control Lists.
* Inheritance.
* Allow rules.
* Deny rules.

Conceptually:

```text id="9a9bq3"
File / Directory
       ↓
Security Descriptor
       ↓
      ACL
       ↓
 ┌─────┴─────┐
 ▼           ▼
Allow       Deny
Entries     Entries
```

Understanding the ACL is more important than simply checking whether a file exists.

---

## 3. Inspect Permissions with `icacls`

The primary native tool for this stage is:

```cmd id="0o8n9b"
icacls <path>
```

Example:

```cmd id="y5j7e1"
icacls "C:\Program Files\Example"
```

For a file:

```cmd id="f3l4r2"
icacls "C:\Program Files\Example\service.exe"
```

---

## 4. Common `icacls` Permissions

Some commonly encountered permission indicators include:

```text id="y1v9g4"
F   Full access
M   Modify
RX  Read and execute
R   Read
W   Write
```

Examples:

```text id="4r7h3m"
BUILTIN\Users:(RX)
```

means the Users group has read/execute access.

Whereas:

```text id="7d3p8f"
BUILTIN\Users:(M)
```

indicates Modify access.

Always interpret the permission in context.

---

## 5. Effective Access

The permission assigned directly to the current user is not the whole story.

Access can be inherited through:

```text id="v6g4j0"
Current User
    │
    ├── Direct ACL
    │
    └── Group Membership
             │
             └── Group ACL
```

Therefore:

```text id="g0q3l8"
User permissions
+
Group permissions
+
Inheritance
+
Deny entries
=
Effective access
```

Do not assume that a single ACL entry represents the complete access level.

---

## 6. Check Current Identity

Before interpreting ACLs, establish the current token:

```cmd id="m8l0z4"
whoami
```

```cmd id="3x0q6k"
whoami /groups
```

This allows ACL entries to be correlated with the current user and groups.

---

## 7. Inspect Important Directories

Start with common locations:

```cmd id="6p3f5g"
icacls "C:\Users"
```

```cmd id="2a7m1f"
icacls "C:\ProgramData"
```

```cmd id="p6x8r3"
icacls "C:\Program Files"
```

```cmd id="j8q1z0"
icacls "C:\Program Files (x86)"
```

```cmd id="f1r5c7"
icacls "C:\Windows"
```

The objective is not to dump every ACL on the system.

Focus on resources that intersect with an execution path.

---

## 8. User-Writable Locations

Common user-controlled locations include:

```text id="b4z7k2"
%TEMP%
%TMP%
%USERPROFILE%
%APPDATA%
%LOCALAPPDATA%
%USERPROFILE%\Downloads
```

These directories are commonly writable by the current user.

That does not make them privilege escalation vulnerabilities.

The important question is:

> **Does a privileged process or task rely on anything from this location?**

---

## 9. ProgramData

`C:\ProgramData` deserves attention because applications frequently store:

* Configuration.
* Logs.
* Application data.
* Shared resources.
* Temporary data.

Inspect:

```cmd id="m0s7d8"
icacls "C:\ProgramData"
```

Then investigate relevant application directories.

Do not assume that every writable application directory provides a privilege escalation path.

---

## 10. Program Files

Inspect application directories:

```cmd id="1f6v2q"
dir "C:\Program Files"
```

and:

```cmd id="6e4h8y"
dir "C:\Program Files (x86)"
```

For an interesting application:

```cmd id="x4s7k1"
icacls "C:\Program Files\Example"
```

Then inspect relevant files:

```cmd id="p9m3z6"
icacls "C:\Program Files\Example\example.exe"
```

The relationship to investigate is:

```text id="j7n2b4"
Privileged Application
        ↓
Application File
        ↓
Writable by Current User?
        ↓
Can Modification Affect Execution?
```

---

## 11. Executable Permissions

If an executable is launched by a privileged process:

```cmd id="r4x9c2"
icacls "C:\Path\program.exe"
```

Determine:

```text id="6k8v1p"
Can current user modify it?
Can a group containing current user modify it?
Can current user delete it?
Can current user replace it?
Can current user rename it?
```

Do not modify the file merely to test access.

Validation should follow the rules of the assessment.

---

## 12. Directory Permissions

Checking the executable alone is insufficient.

For:

```text id="j0k3s6"
C:\Application\program.exe
```

also check:

```cmd id="0m7x4p"
icacls "C:\Application"
```

and, when relevant:

```cmd id="7t5n2k"
icacls "C:\"
```

The full path should be considered:

```text id="f7q2m5"
C:\
 ↓
Application\
 ↓
program.exe
```

A writable directory may allow modification of a file even when the file's own ACL appears restrictive.

---

## 13. Parent Directory Analysis

For an interesting file:

```text id="y8f1z4"
C:\A\B\C\program.exe
```

consider:

```text id="8x2q9v"
C:\
A\
B\
C\
program.exe
```

Check the relevant directories.

This helps identify cases where the file itself is protected but the path leading to it is not.

---

## 14. File Replacement vs File Modification

Distinguish between:

```text id="w2c4p6"
Modify existing file
```

and:

```text id="q7r1x8"
Replace file
```

The required permissions can differ.

For a potential escalation path, determine exactly what operation the current user can perform and whether that operation changes what a privileged process executes.

---

## 15. Delete and Rename Permissions

A user may not have direct write access to a file but may have permissions on the containing directory that allow file deletion or renaming.

Therefore investigate:

```text id="d4m8s2"
File ACL
+
Directory ACL
=
Practical ability to alter execution
```

This is especially relevant when investigating:

* Services.
* Scheduled tasks.
* Application executables.
* DLLs.
* Configuration files.

---

## 16. ACL Inheritance

Windows permissions can be inherited from parent directories.

Conceptually:

```text id="q9k4h1"
Parent Directory
       │
       ▼
Inherited ACL
       │
       ▼
Child Directory
       │
       ▼
File
```

Use:

```cmd id="4y1m8k"
icacls "<path>"
```

and examine whether permissions are inherited.

Inheritance can explain why a file has permissions that were not explicitly assigned to it.

---

## 17. Ownership

Check ownership where relevant:

```cmd id="u3k8p5"
icacls "<path>"
```

The owner is shown in the ACL/security descriptor information where available.

Remember:

```text id="p8d2s7"
Ownership
    ≠
Full control
```

Ownership can provide additional control over an object, but it does not automatically grant every permission.

---

## 18. Sensitive System Locations

Some locations deserve attention because they contain security-sensitive resources.

Examples include:

```text id="7w6m2f"
C:\Windows\
C:\Windows\System32\
C:\Windows\System32\config\
C:\Windows\Tasks\
C:\Windows\System32\Tasks\
C:\ProgramData\
```

Do not modify or extract sensitive system files unnecessarily.

The goal is to understand permissions and execution relationships.

---

## 19. Search for Interesting Files

File searches should be targeted rather than indiscriminate.

Potentially relevant file types include:

```text id="2x4n8q"
*.config
*.ini
*.xml
*.ps1
*.bat
*.cmd
*.vbs
*.txt
```

Application-specific files may also be relevant.

For example:

```cmd id="5n8x2c"
dir C:\ProgramData /s /b
```

can produce a large amount of output.

Prefer targeted searches once an application or execution path has been identified.

---

## 20. Configuration Files

Configuration files can contain:

* Service configuration.
* Database credentials.
* API keys.
* Paths.
* Connection strings.
* Application secrets.
* Execution parameters.

When a potentially sensitive file is found:

```text id="4f9z3r"
Identify owner
      ↓
Inspect ACL
      ↓
Determine who can read/modify it
      ↓
Determine what application uses it
      ↓
Assess security impact
```

Credential-related investigation will be covered more fully in:

```text id="q0m2z7"
10-Credentials-and-Secrets/
```

---

## 21. Writable Resource + Privileged Execution

This is one of the most important relationships in the repository.

```text id="w3k6p1"
Writable Resource
       +
Privileged Execution
       ↓
Potential Privilege Boundary
```

Examples:

```text id="z5t8n2"
Writable Service Executable
        +
SYSTEM Service
```

```text id="s4h9c3"
Writable Scheduled-Task Script
        +
SYSTEM Task
```

```text id="m6q1v7"
Writable DLL
        +
Privileged Application
```

The filesystem finding becomes important because of the **privileged execution context**.

---

## 22. Common Permission Findings

Potential findings include:

* Writable privileged executable.
* Writable service directory.
* Writable scheduled-task resource.
* Writable DLL search location.
* Writable application configuration.
* Weak permissions on security-sensitive files.
* Insecure directory inheritance.
* Excessive permissions granted to a low-privileged group.
* Resource ownership that creates an unexpected control path.

Every finding must be validated.

---

## 23. Common False Positives

```text id="j3v8x0"
Writable file
    ≠
Privilege escalation

Writable directory
    ≠
Privilege escalation

Modify permission
    ≠
Guaranteed execution

User owns file
    ≠
Privileged process uses file

Readable configuration
    ≠
Usable credential

Interesting ACL
    ≠
Confirmed vulnerability
```

Always connect the permission to an actual security boundary.

---

## 24. Permission Investigation Workflow

Use:

```text id="k7q5r2"
Identify Resource
      ↓
Identify Owner
      ↓
Inspect ACL
      ↓
Map Current User / Groups
      ↓
Determine Effective Access
      ↓
Identify Who Uses the Resource
      ↓
Determine Execution Context
      ↓
Assess Privilege Boundary
      ↓
Validate
```

---

## 25. Build a Permission Map

For each interesting resource:

```text id="n2w7c4"
PERMISSION MAP
--------------

Resource:
Type:
Owner:

ACL:

Current User:
Relevant Groups:

Effective Permission:

Used By:
Process / Service / Task / Application:

Execution Account:

Writable?
Readable?
Executable?
Deletable?
Replaceable?

Potential Privilege Boundary:

Validation Required:
```

---

## 26. Relating Permissions to Previous Stages

Filesystem analysis should connect back to previous findings.

### Services

```text
Service
 ↓
Executable
 ↓
ACL
```

### Scheduled Tasks

```text
Task
 ↓
Script / Executable
 ↓
ACL
```

### Processes

```text
Process
 ↓
Executable / DLL
 ↓
ACL
```

### Applications

```text
Application
 ↓
Configuration / Executable
 ↓
ACL
```

This makes filesystem enumeration part of the larger workflow rather than an isolated permission audit.

---

## 27. Decision Tree

```text id="z3y9m6"
                 Interesting Resource
                         │
                         ▼
                    Inspect ACL
                         │
                         ▼
                Can current user
                 influence it?
                    /       \
                  No         Yes
                  │           │
                  ▼           ▼
             Continue      Who uses it?
             enumeration        │
                                ▼
                       Privileged process?
                            /       \
                          No         Yes
                          │           │
                          ▼           ▼
                     Record       Validate
                                   path
```

---

## 28. Filesystem Checklist

```text id="q8n1d5"
[ ] Current user and groups confirmed
[ ] Important directories identified
[ ] ProgramData reviewed
[ ] Program Files reviewed
[ ] User-controlled locations reviewed
[ ] Interesting executables identified
[ ] Executable ACLs checked
[ ] Directory ACLs checked
[ ] Parent directories checked
[ ] File ownership considered
[ ] ACL inheritance considered
[ ] Delete/rename permissions considered
[ ] Configuration files identified
[ ] Relevant file permissions documented
[ ] Privileged execution relationships identified
[ ] Writable-resource leads documented
[ ] False positives eliminated
```

---

## 29. Decision Point

At the end of this stage:

```text id="s8v5q3"
                 Filesystem Resource
                         │
                         ▼
                       ACL
                         │
                         ▼
                Current User Access
                         │
               ┌─────────┴─────────┐
               │                   │
               ▼                   ▼
          No Influence        Can Influence
               │                   │
               ▼                   ▼
          Continue             Who uses it?
          Enumeration               │
                                    ▼
                            Privileged Context?
                              /          \
                            No            Yes
                            │              │
                            ▼              ▼
                         Record         Validate
```

---

## Next Step

Proceed to:

```text id="u5y7c1"
09-Registry/
```

The next stage investigates the **Windows Registry as a security boundary**.

The central question becomes:

> **Which security-relevant registry keys and values can the current user access or modify, and are any of them consumed by privileged services, applications, startup mechanisms, or other execution paths?**
