# Registry

The Windows Registry is a hierarchical database used by Windows and applications to store configuration, security-related settings, service configuration, startup information, and application data.

Registry configuration can become relevant to privilege escalation when a privileged process relies on a registry key or value that a lower-privileged user can modify.

The objective of this stage is to answer:

> **Which registry locations are relevant to privileged execution, who can modify them, and what does a privileged component do with the modified configuration?**

---

## 1. Investigation Model

Use the following model:

```text
Registry Key / Value
        ↓
Owner / ACL
        ↓
Current User / Groups
        ↓
Effective Access
        ↓
Who Reads the Value?
        ↓
Execution Context
        ↓
Potential Privilege Boundary
```

A writable registry key is not automatically a privilege escalation vulnerability.

The key must have a security-relevant effect.

---

## 2. Registry Structure

The Registry is organized into root keys called hives.

Common root keys include:

```text id="s9y6c4"
HKEY_LOCAL_MACHINE (HKLM)
HKEY_CURRENT_USER  (HKCU)
HKEY_CLASSES_ROOT  (HKCR)
HKEY_USERS         (HKU)
HKEY_CURRENT_CONFIG (HKCC)
```

For privilege escalation, `HKLM` is particularly important because it contains system-wide configuration.

`HKCU` contains configuration associated with the current user and is generally user-controlled.

---

## 3. Basic Registry Enumeration

Use the native `reg` utility.

List a key:

```cmd id="6k2y3p"
reg query "HKLM\SOFTWARE"
```

Query a specific key:

```cmd id="j4r7x8"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"
```

Display values:

```cmd id="3q8m1n"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" /v ProgramFilesDir
```

The objective is targeted enumeration rather than dumping the entire Registry.

---

## 4. Registry Permissions

Use:

```cmd id="v7c5n2"
icacls "<registry-path>"
```

where supported by the Windows environment and tool usage.

Registry security descriptors can also be examined using:

```cmd id="9w4p6z"
regini
```

and PowerShell/security APIs where appropriate.

For a specific registry key, the important question is:

> **Can the current user or one of their groups modify the key or relevant values?**

---

## 5. Registry ACL Reasoning

Use the same reasoning model as filesystem permissions:

```text id="0b9f4q"
Registry Key
     ↓
Security Descriptor
     ↓
ACL
     ↓
Current User / Groups
     ↓
Effective Permission
```

Do not confuse:

```text id="4k6d8v"
Read Access
    ≠
Write Access
    ≠
Full Control
```

A readable registry key is not necessarily a security weakness.

---

## 6. Service Registry Configuration

Services store configuration under:

```text id="f3h7s2"
HKLM\SYSTEM\CurrentControlSet\Services\
```

For a specific service:

```cmd id="9n2r6c"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<service_name>"
```

Important values may include:

```text id="v5m1q7"
ImagePath
ObjectName
Start
Type
DependOnService
```

This connects directly to:

```text id="s2x8n4"
06-Processes-and-Services/
```

For example:

```text id="1g5m9q"
Service
  ↓
Registry Configuration
  ↓
Executable Path
  ↓
Service Account
  ↓
Permissions
```

---

## 7. Service Registry Permissions

If a service appears interesting, investigate both:

```text id="w6p8z3"
Service Security Descriptor
```

and:

```text id="4v7c1m"
Service Registry Key ACL
```

These are different security layers.

A service may have a protected configuration while its registry representation has different permissions, or vice versa.

Do not assume one implies the other.

---

## 8. ImagePath

The `ImagePath` value can identify the executable associated with a service.

Example:

```cmd id="h4j6t1"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<service_name>" /v ImagePath
```

Then follow the path:

```text id="8d3q7p"
ImagePath
   ↓
Executable
   ↓
Directory
   ↓
ACL
   ↓
Execution Account
```

This creates a direct connection between registry enumeration and service analysis.

---

## 9. Service Account Configuration

Some services specify their execution account through:

```text id="y8r4c6"
ObjectName
```

Query it:

```cmd id="2m7v5x"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<service_name>" /v ObjectName
```

The relationship becomes:

```text id="9j3n7a"
Registry
   ↓
ObjectName
   ↓
Service Account
   ↓
Service Process
```

If a lower-privileged user can modify security-relevant service configuration, investigate whether the change can affect privileged execution.

---

## 10. Startup Locations

Windows contains several registry locations associated with application startup.

Examples include:

```text id="r1s8c5"
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

Query them:

```cmd id="x6z2m9"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

```cmd id="a5p9q4"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
```

Current-user startup configuration can also be inspected:

```cmd id="c7n3v1"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

The important question is:

> **Who consumes the startup configuration, and under which security context?**

A user-controlled startup entry does not automatically provide system-level escalation.

---

## 11. Startup Registry Reasoning

Use:

```text id="f7x4j9"
Registry Startup Entry
        ↓
Who reads it?
        ↓
When is it executed?
        ↓
Under which account?
        ↓
Can current user modify it?
        ↓
What security boundary exists?
```

This avoids the common mistake of treating every `Run` key as a privilege escalation mechanism.

---

## 12. Application Configuration

Applications frequently store configuration under:

```text id="4h8q2m"
HKLM\SOFTWARE\
HKLM\SOFTWARE\WOW6432Node\
HKCU\SOFTWARE\
```

Examples may include:

* Installation paths.
* Service configuration.
* Update settings.
* Plugin locations.
* Executable paths.
* Configuration values.
* Application-specific credentials.

When an interesting application is found:

```text id="v5q8n1"
Application
    ↓
Registry Configuration
    ↓
Permissions
    ↓
Who consumes it?
    ↓
Execution Context
```

---

## 13. WOW6432Node

On 64-bit Windows systems, 32-bit applications may use registry redirection.

A commonly relevant location is:

```text id="2j7k5m"
HKLM\SOFTWARE\WOW6432Node\
```

When investigating an application, determine whether it is:

```text id="p8s1d6"
32-bit
or
64-bit
```

and inspect the corresponding registry configuration.

Do not assume that a value in one registry view represents the same configuration consumed by every process.

---

## 14. Registry Environment Configuration

Some Windows environment configuration is stored in:

```text id="m6r4t9"
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
```

Query:

```cmd id="y9q3v7"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
```

This can help correlate registry configuration with environment variables.

Any security-relevant modification should be analyzed in terms of:

```text
Who modifies it?
Who consumes it?
When is it consumed?
Under what security context?
```

---

## 15. Unquoted Service Paths and Registry

The registry may contain the service's `ImagePath`.

For example:

```cmd id="q2k7m5"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<service_name>" /v ImagePath
```

If the value contains a path with spaces, investigate whether the path is correctly quoted.

Use the chain:

```text id="a4n8c1"
Registry ImagePath
      ↓
Service Executable
      ↓
Path Parsing
      ↓
Candidate Locations
      ↓
Filesystem Permissions
      ↓
Potential Execution Influence
```

Registry enumeration therefore connects directly with the filesystem workflow.

---

## 16. AlwaysInstallElevated

Windows Installer policies can be security-relevant when specific machine and user policy values are configured.

Relevant locations include:

```text id="q9m3x5"
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

Query them:

```cmd id="v6k1p8"
reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer"
```

```cmd id="f8r2y4"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer"
```

The important point is that the security impact depends on the relevant policy configuration and both scopes.

Do not treat the existence of the registry path as evidence of a vulnerability.

---

## 17. Registry Permissions vs Registry Values

Distinguish between:

```text id="t4z7m2"
Key is writable
```

and:

```text id="b8q3v6"
Specific value is security-relevant
```

For example:

```text id="n7p2x5"
Writable Registry Key
       ↓
Can modify ImagePath
       ↓
Privileged Service
       ↓
Potential Escalation
```

Whereas:

```text id="h5m9c2"
Writable Registry Key
       ↓
Only changes cosmetic setting
       ↓
No privilege boundary
```

Only the first type represents a potentially meaningful escalation path.

---

## 18. Registry Credential Discovery

Registry entries may contain:

* Connection strings.
* Application credentials.
* Configuration secrets.
* Paths to credential stores.

If credentials are encountered:

```text id="x3r8v1"
Identify Secret
      ↓
Determine Owner / Application
      ↓
Determine Intended Use
      ↓
Assess Security Impact
```

Do not unnecessarily expose discovered secrets.

Credential-focused analysis belongs in:

```text id="0q7m5z"
10-Credentials-and-Secrets/
```

---

## 19. Registry Search

Avoid immediately searching the entire Registry indiscriminately.

Instead, search based on a known lead.

Examples:

```cmd id="6k9p3x"
reg query HKLM /f "Example" /s
```

or:

```cmd id="1v4n8q"
reg query HKCU /f "Example" /s
```

Large searches can produce substantial output and make relevant findings harder to identify.

Use targeted searches whenever possible.

---

## 20. Registry Finding Validation

When an interesting registry entry is found:

```text id="y4c8s6"
Identify Key
     ↓
Identify Value
     ↓
Inspect ACL
     ↓
Determine Current User Access
     ↓
Identify Consumer
     ↓
Determine Consumer Privilege
     ↓
Determine Effect of Modification
     ↓
Validate
```

This is the standard registry reasoning workflow.

---

## 21. Common Registry Findings

Potential findings include:

* Weak permissions on service registry keys.
* Modifiable service configuration.
* Security-relevant startup configuration.
* Weak application configuration permissions.
* Insecure installer policy configuration.
* Registry-based execution paths relying on writable resources.
* Exposed application secrets.
* Registry values that redirect privileged execution.

Each must be validated against the actual execution behavior.

---

## 22. Common False Positives

```text id="8j2q5m"
Writable HKCU key
    ≠
System-level privilege escalation

Writable registry key
    ≠
Security vulnerability

Run key exists
    ≠
Privileged execution

Interesting ImagePath
    ≠
Exploitable service

Credential-looking value
    ≠
Usable privileged credential

HKLM entry
    ≠
Automatically exploitable
```

Always establish the consumer and execution context.

---

## 23. Registry Investigation Map

For an interesting key:

```text id="d6f3x9"
REGISTRY MAP
------------

Hive:
Key:
Value:

Owner:
ACL:

Current User:
Relevant Groups:

Effective Access:

Consumer:
Process / Service / Application:

Execution Account:

Security-Relevant Effect:

Potential Writable Configuration:

Potential Privilege Boundary:

Validation Required:
```

---

## 24. Registry Decision Tree

```text id="v5h7q2"
                  Registry Key
                       │
                       ▼
                  Security ACL
                       │
                       ▼
               Can current user
                 modify it?
                  /       \
                No         Yes
                │           │
                ▼           ▼
             Continue    What does it
             analysis     control?
                            │
                ┌───────────┼───────────┐
                │           │           │
                ▼           ▼           ▼
             Service     Startup     Application
                │           │           │
                └───────────┼───────────┘
                            ▼
                   Who consumes it?
                            │
                            ▼
                    Privileged context?
                       /          \
                     No            Yes
                     │              │
                     ▼              ▼
                  Record         Validate
```

---

## 25. Registry Checklist

```text id="e7k2n4"
[ ] Registry structure understood
[ ] Relevant hives identified
[ ] Service registry configuration reviewed
[ ] ImagePath values investigated
[ ] ObjectName values investigated
[ ] Service registry permissions considered
[ ] Startup locations reviewed
[ ] Application registry configuration reviewed
[ ] WOW6432Node considered where applicable
[ ] Environment-related registry configuration reviewed
[ ] AlwaysInstallElevated policy checked
[ ] Relevant registry ACLs investigated
[ ] Potential registry-based execution paths documented
[ ] Credential-related values noted for later analysis
[ ] False positives eliminated
[ ] Registry maps created for interesting findings
```

---

## 26. Decision Point

After registry enumeration:

```text id="c8n4z1"
                    Registry
                       │
                       ▼
                 Interesting Key
                       │
                       ▼
                      ACL
                       │
            ┌──────────┴──────────┐
            │                     │
            ▼                     ▼
       Not Writable            Writable
            │                     │
            ▼                     ▼
        Continue            Identify Consumer
        Enumeration                │
                                   ▼
                           Privileged Consumer?
                              /          \
                            No            Yes
                            │              │
                            ▼              ▼
                         Record         Validate
```

---

## Next Step

Proceed to:

```text id="r6k1p9"
10-Credentials-and-Secrets/
```

The next stage focuses on **credential and secret discovery**.

The central question becomes:

> **Where might authentication material be stored or exposed, who can access it, and does it provide access to a more privileged security context?**
