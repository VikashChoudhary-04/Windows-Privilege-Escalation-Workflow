# Windows Privilege Escalation Workflow

A practical, workflow-driven guide to Windows privilege escalation enumeration, analysis, validation, and reporting.

---

## Overview

Windows privilege escalation is the process of obtaining higher privileges on a Windows system than those initially provided.

This repository presents Windows privilege escalation as a **structured investigation workflow** rather than a collection of commands or isolated techniques.

The objective is to develop a repeatable methodology:

```text
Enumerate
   ↓
Understand
   ↓
Identify
   ↓
Validate
   ↓
Exploit
   ↓
Verify
   ↓
Document
```

The workflow begins with understanding the current security context and system configuration, then progressively investigates users, privileges, processes, services, scheduled tasks, files, registry configuration, credentials, applications, networking, and Windows-specific security misconfigurations.

---

## Objectives

This repository aims to help develop the ability to:

* Understand the current Windows security context.
* Systematically enumerate a Windows host.
* Identify privilege boundaries and security-relevant configurations.
* Recognize common Windows privilege escalation opportunities.
* Understand why a configuration may be exploitable.
* Validate potential escalation paths safely.
* Distinguish genuine findings from false positives.
* Verify successful privilege escalation.
* Document findings clearly and reproducibly.

---

## Workflow

The complete workflow is organized into the following stages:

```text
00  Scope & Authorization
        ↓
01  Initial Access Context
        ↓
02  First 5 Minutes
        ↓
03  System Enumeration
        ↓
04  Users & Groups
        ↓
05  Privileges & Access Tokens
        ↓
06  Processes & Services
        ↓
07  Scheduled Tasks
        ↓
08  Filesystem & Permissions
        ↓
09  Registry
        ↓
10  Credentials & Secrets
        ↓
11  Applications & Installed Software
        ↓
12  Network Enumeration
        ↓
13  Windows Misconfigurations
        ↓
14  Validation & Exploitation
        ↓
15  Post-Exploitation Verification
        ↓
16  Reporting & Cleanup
```

The stages provide structure, but they are not necessarily strictly linear.

A finding discovered during one stage may require returning to an earlier stage for additional enumeration or validation.

---

## Core Methodology

Every investigation should follow the same basic reasoning process.

### 1. Enumerate

Collect information about the system.

Examples include:

* Operating system information
* Current user
* Group memberships
* Privileges
* Running processes
* Services
* Scheduled tasks
* File and directory permissions
* Registry configuration
* Installed applications
* Network configuration

### 2. Understand

Determine what the collected information means.

For example:

```text
Service
   ↓
Service account
   ↓
Executable location
   ↓
Executable permissions
   ↓
Directory permissions
   ↓
Service control permissions
```

A suspicious configuration is not automatically an escalation vulnerability.

### 3. Identify

Look for configurations that cross a privilege boundary.

Examples include:

* A privileged service using a writable executable.
* A privileged process loading a modifiable library.
* A scheduled task executing content that a lower-privileged user can modify.
* Weak permissions on security-sensitive resources.
* Excessive user privileges.
* Exposed credentials or secrets.
* Misconfigured Windows security settings.

### 4. Validate

Determine whether the suspected weakness is actually exploitable.

Validation should establish:

* What privilege is required?
* What privilege does the vulnerable component have?
* What can the current user modify?
* What security boundary is crossed?
* What conditions are required?
* Is exploitation reproducible?

### 5. Exploit

Where explicitly authorized, use the validated weakness to demonstrate privilege escalation.

The goal is not exploitation for its own sake.

The goal is to demonstrate that the identified security weakness can cross the intended privilege boundary.

### 6. Verify

Confirm the resulting security context.

For example:

```text
Initial Context
      ↓
Low-privileged user
      ↓
Exploit validated weakness
      ↓
New security context
      ↓
Confirm effective privileges
```

### 7. Document

Record:

* Initial access level
* Enumeration performed
* Relevant configuration
* Identified weakness
* Validation steps
* Result
* Root cause
* Security impact
* Remediation

---

## Repository Structure

The repository is organized around the investigation workflow.

```text
Windows-Privilege-Escalation-Workflow/
│
├── README.md
│
├── 00-Scope-and-Authorization/
│   └── README.md
│
├── 01-Initial-Access-Context/
│   └── README.md
│
├── 02-First-5-Minutes/
│   └── README.md
│
├── 03-System-Enumeration/
│   └── README.md
│
├── 04-Users-and-Groups/
│   └── README.md
│
├── 05-Privileges-and-Access-Tokens/
│   └── README.md
│
├── 06-Processes-and-Services/
│   └── README.md
│
├── 07-Scheduled-Tasks/
│   └── README.md
│
├── 08-Filesystem-and-Permissions/
│   └── README.md
│
├── 09-Registry/
│   └── README.md
│
├── 10-Credentials-and-Secrets/
│   └── README.md
│
├── 11-Applications-and-Installed-Software/
│   └── README.md
│
├── 12-Network-Enumeration/
│   └── README.md
│
├── 13-Windows-Misconfigurations/
│   └── README.md
│
├── 14-Validation-and-Exploitation/
│   └── README.md
│
├── 15-Post-Exploitation-Verification/
│   └── README.md
│
├── 16-Reporting-and-Cleanup/
│   └── README.md
│
├── 02-Progress/
│   └── labs-solved.csv
│
└── 99-References/
    └── README.md
```

The directories will be developed progressively as the workflow is completed.

---

## Windows Privilege Escalation Areas

The workflow covers major Windows privilege escalation categories, including:

### Security Context

* Current user
* Groups
* Integrity levels
* User rights
* Access tokens
* Privileges

### System Configuration

* Windows version
* Architecture
* Environment variables
* Security configuration
* Installed updates
* Host configuration

### Services

* Service configuration
* Service accounts
* Service executable paths
* Service permissions
* Executable permissions
* Directory permissions
* Service-related DLL loading behavior

### Scheduled Tasks

* Task configuration
* Task execution context
* Task actions
* Trigger conditions
* Writable task resources

### Filesystem

* NTFS permissions
* ACLs
* Writable files
* Writable directories
* Executable locations
* Sensitive files

### Registry

* Registry permissions
* Security-sensitive configuration
* Service-related registry entries
* Application configuration
* Startup-related locations

### Credentials & Secrets

* Configuration files
* Application credentials
* Stored secrets
* Credential artifacts
* Password-related exposure

### Applications

* Installed software
* Application configuration
* Vulnerable or misconfigured software
* Application-specific privilege boundaries

### Networking

* Interfaces
* Routing
* Listening services
* Local connections
* Network configuration
* Security-relevant network exposure

### Windows-Specific Misconfigurations

The workflow also investigates configuration weaknesses such as:

* Weak service permissions
* Writable service resources
* Unquoted service paths
* DLL search-order-related weaknesses
* Weak scheduled-task configurations
* Excessive privileges
* Insecure registry permissions
* Misconfigured Windows Installer policies
* Other privilege-boundary violations

Each technique will be investigated in context rather than treated as an isolated trick.

---

## Tools

Tools may be introduced where they improve enumeration, analysis, or validation.

The repository may cover native Windows utilities as well as commonly used security tools.

Examples include:

```text
whoami
systeminfo
hostname
ipconfig
net
sc
schtasks
tasklist
wmic
reg
icacls
findstr
PowerShell
```

Security-oriented tooling may be introduced where appropriate for authorized security testing.

Tools are considered **supporting components of the workflow**, not replacements for understanding the underlying Windows security model.

---

## Lab Environment

The techniques in this repository should be practiced only in environments where testing is authorized.

Suitable environments include:

* Personal Windows virtual machines
* Intentionally vulnerable Windows systems
* Authorized cybersecurity training labs
* Controlled penetration-testing environments

The repository focuses on understanding the underlying Windows mechanisms so that the methodology remains useful across different environments.

---

## Safety & Authorization

All enumeration, validation, and exploitation activities must be performed only against systems for which you have explicit authorization.

Do not use the techniques in this repository against:

* Systems you do not own.
* Systems without explicit testing authorization.
* Production environments without an approved testing scope.
* Third-party systems without permission.

When performing an authorized assessment, follow the defined scope, rules of engagement, and cleanup requirements.

---

## Learning Approach

The repository is designed around **reasoning over memorization**.

Instead of memorizing:

```text
"Run this command for this exploit."
```

the goal is to understand:

```text
What am I looking at?
        ↓
Why is it interesting?
        ↓
What privilege does it have?
        ↓
What can I modify?
        ↓
Can that modification cross a privilege boundary?
        ↓
How can I safely validate it?
```

This approach makes the workflow more adaptable when the target system differs from a known lab environment.

---

## Progress Tracking

Practical progress will be tracked separately from the workflow documentation.

```text
02-Progress/
└── labs-solved.csv
```

The progress tracker will record completed Windows privilege escalation labs and relevant observations.

---

## References

External documentation, technical references, and authoritative Windows security resources will be collected under:

```text
99-References/
```

References will be added as individual workflow sections are developed.

---

## Status

**Repository Status:** 🚧 In Progress

The workflow is being developed progressively, starting with the fundamentals and moving toward advanced Windows privilege escalation techniques.

---

## Disclaimer

This repository is intended for cybersecurity education, authorized security testing, and controlled laboratory environments.

The author is responsible for ensuring that all activities performed using the material in this repository are properly authorized.
