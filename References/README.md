# References

This directory contains reference material that supports the **Windows Privilege Escalation Workflow**.

References are not a separate phase of the workflow. They are supporting resources that can be consulted during enumeration, analysis, validation, exploitation, verification, and reporting.

---

## Purpose

The purpose of this directory is to maintain reliable references for:

* Windows security concepts
* Windows privilege and token behavior
* NTFS permissions and ACLs
* Windows services
* Scheduled tasks
* Registry security
* User and group management
* Windows authentication
* Credential storage
* Process and security boundaries
* Windows networking
* Security descriptors
* PowerShell and Windows administration
* Privilege escalation research
* Vulnerability and weakness references
* Defensive guidance and remediation

The goal is to use references to **understand why a finding matters**, not simply to copy commands or techniques.

---

## Reference Principles

When adding a reference, prioritize:

1. **Official documentation**
2. **Primary technical sources**
3. **Established security standards**
4. **Reputable security research**
5. **Well-maintained technical references**

Prefer sources that explain the underlying Windows behavior rather than sources that only provide exploitation commands.

---

## Recommended Reference Categories

### Windows Documentation

Useful for understanding Windows internals, administration, security controls, and system behavior.

Examples:

* Microsoft Learn
* Windows security documentation
* PowerShell documentation
* Windows command documentation
* Windows API documentation

---

### Windows Security

References for:

* Access tokens
* Security identifiers (SIDs)
* Integrity levels
* User Account Control (UAC)
* Privileges
* Security descriptors
* Access control lists (ACLs)
* Authentication
* Authorization
* Windows security boundaries

---

### Filesystem and Permissions

References for:

* NTFS permissions
* File and directory ACLs
* Ownership
* Inheritance
* Effective access
* `icacls`
* File and directory security behavior

---

### Services

References for:

* Windows Service Control Manager
* Service configuration
* Service accounts
* Service security descriptors
* Service executable paths
* Service dependencies
* Service startup behavior

---

### Scheduled Tasks

References for:

* Task Scheduler
* Task principals
* Task actions
* Task triggers
* Task security
* Scheduled-task execution contexts

---

### Registry

References for:

* Registry architecture
* Registry permissions
* Registry security descriptors
* Service configuration
* Startup locations
* Application configuration
* Registry-based security controls

---

### Credentials and Secrets

References for understanding:

* Windows credential storage
* Credential Manager
* Authentication mechanisms
* Service credentials
* Application configuration
* Secrets stored in files or registry locations

Credential references should be used to understand **storage and security behavior**. They should not be treated as justification for collecting credentials outside the authorized assessment scope.

---

### Applications and Software

References for:

* Windows application installation
* Software configuration
* DLL loading behavior
* Search order
* Application permissions
* Update mechanisms
* Common Windows application security issues

---

### Networking

References for:

* Windows networking
* SMB
* RPC
* WinRM
* RDP
* WMI
* Windows Firewall
* Network shares
* Windows network authentication

---

### Privilege Escalation Research

Use this category for technical research concerning:

* Windows privilege boundaries
* Common misconfigurations
* Service-related weaknesses
* Permission weaknesses
* Token-related security issues
* Registry weaknesses
* Application-related privilege boundaries
* Known vulnerabilities

Research should always be evaluated against the actual configuration and Windows version being assessed.

---

## Reference Quality Checklist

Before adding a reference, ask:

* Is the source technically credible?
* Is the information applicable to Windows?
* Does it explain the underlying behavior?
* Is the information sufficiently current for the Windows version involved?
* Is the source maintained?
* Can the information be independently verified?
* Does it help understand or validate something in this workflow?

Avoid adding references simply because they contain a large collection of commands.

---

## Version Awareness

Windows behavior can vary between:

* Windows versions
* Windows editions
* Security configurations
* Domain-joined and standalone systems
* PowerShell versions
* Security policy configurations
* Patch levels

A reference should therefore be interpreted in the context of the target environment.

When relevant, record:

```text
Windows version:
Build:
Architecture:
PowerShell version:
Domain/Workgroup:
Security configuration:
Patch level:
```

Do not assume that a technique documented for one Windows version automatically applies to another.

---

## Evidence and References

References support findings, but they do not replace evidence from the target system.

A strong assessment separates:

```text
Reference
    ↓
Expected Windows behavior
    ↓
Observed configuration
    ↓
Security implication
    ↓
Validation
    ↓
Finding
```

For example:

```text
Documentation
    ↓
Explains service permissions
    ↓
Target service has a specific ACL
    ↓
Current user can modify the relevant resource
    ↓
Service executes that resource with a higher-privileged account
    ↓
Controlled validation confirms the security boundary
```

The finding should be based on the **observed target configuration**, with references used to explain the underlying behavior.

---

## Suggested Reference Structure

As the repository grows, references can be organized by topic:

```text
99-References/
├── README.md
├── windows-security.md
├── access-tokens.md
├── privileges.md
├── ntfs-permissions.md
├── services.md
├── scheduled-tasks.md
├── registry.md
├── credentials.md
├── networking.md
└── privilege-escalation-research.md
```

These files should only be added when they provide meaningful value. The repository should avoid becoming a collection of duplicated documentation.

---

## Relationship With the Workflow

The workflow remains the primary learning path:

```text
Scope
  ↓
Initial Context
  ↓
Rapid Triage
  ↓
Enumeration
  ↓
Security Analysis
  ↓
Misconfiguration Identification
  ↓
Validation
  ↓
Controlled Exploitation
  ↓
Verification
  ↓
Reporting & Cleanup
```

References support every stage:

```text
                    ┌──────────────────────┐
                    │     References       │
                    └──────────┬───────────┘
                               │
                               ↓
Scope → Enumeration → Analysis → Validation → Verification → Reporting
```

They should therefore remain outside the numbered workflow.

---

## Practical Rule

> **Understand the Windows security model first. Use references to verify your understanding. Use commands to collect evidence. Use validation to prove the security impact.**

That principle keeps the repository focused on **reasoning and methodology**, rather than becoming a command-only privilege-escalation cheat sheet.

---

## Status

**Repository reference structure:** Established

**Workflow status:** Complete through `16-Reporting-and-Cleanup`

**Progress tracking:** `Progress/labs-solved.csv`

**Reference material:** This directory
