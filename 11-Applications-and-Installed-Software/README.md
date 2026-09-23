# Applications and Installed Software

Installed applications and software components can create privilege-escalation opportunities through insecure configurations, privileged execution, writable application resources, vulnerable components, exposed credentials, and weak service integration.

The goal of this stage is **not to treat every outdated application as a vulnerability**.

The goal is to understand:

```text
What is installed?
        ↓
What is running?
        ↓
Which account runs it?
        ↓
Where is it installed?
        ↓
Who can modify it?
        ↓
What configuration does it use?
        ↓
Does it cross a privilege boundary?
```

---

## 1. Objective

Determine:

* Which applications are installed
* Which applications are currently running
* Application versions
* Installation locations
* Associated services and processes
* Application configuration locations
* File and directory permissions
* Application-specific accounts
* Security-sensitive integrations
* Potentially vulnerable or misconfigured components
* Whether the application creates a realistic privilege-escalation path

---

## 2. Installed Software Enumeration

Start with a broad inventory.

### WMIC

On systems where WMIC is available:

```cmd
wmic product get name,version,vendor
```

WMIC availability varies between Windows versions and should not be treated as the only software inventory source.

### PowerShell

Registry-based uninstall information can be queried with:

```powershell
Get-ItemProperty `
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation
```

For 32-bit applications on 64-bit Windows:

```powershell
Get-ItemProperty `
"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation
```

For the current user:

```powershell
Get-ItemProperty `
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation
```

---

## 3. Build an Application Inventory

Create a simple inventory:

| Application   | Version | Location | Running? | Service? | Account | Notes       |
| ------------- | ------- | -------- | -------- | -------- | ------- | ----------- |
| Application A | Version | Path     | Yes/No   | Yes/No   | Account | Observation |
| Application B | Version | Path     | Yes/No   | Yes/No   | Account | Lead        |

The inventory becomes more useful when connected to information collected in earlier stages.

---

## 4. Prioritize Applications

Do not investigate every installed application equally.

Prioritize applications that are:

```text
Running
        ↓
Privileged
        ↓
Network-facing
        ↓
Security-sensitive
        ↓
Custom-built
        ↓
Poorly maintained
        ↓
Associated with writable files/configuration
```

Examples of potentially interesting software include:

```text
Web servers
Database servers
Backup software
Monitoring agents
Remote administration tools
Development platforms
CI/CD agents
Virtualization software
Security software
File synchronization software
Custom enterprise applications
```

The application category alone does not establish a vulnerability.

---

## 5. Installation Paths

Determine where important applications are installed.

Common locations include:

```text
C:\Program Files\
C:\Program Files (x86)\
C:\ProgramData\
C:\Users\<user>\AppData\
C:\Windows\
Custom application directories
```

Inspect permissions:

```cmd
icacls "C:\Path\To\Application"
```

Then inspect important files:

```cmd
icacls "C:\Path\To\Application\app.exe"
```

The important question is:

> Can the current user modify an application resource that executes with higher privileges?

---

## 6. Application Executables

Identify the executable associated with the application.

Useful commands:

```cmd
where <application>
```

PowerShell:

```powershell
Get-Command <application>
```

For running processes:

```powershell
Get-Process
```

More detailed process information:

```powershell
Get-CimInstance Win32_Process |
Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine
```

Determine:

* Executable path
* Process owner
* Command-line arguments
* Parent process
* Privilege context
* Related configuration files

---

## 7. Application-to-Process Mapping

Build a relationship between installed software and running processes:

```text
Installed Application
        ↓
Executable
        ↓
Process
        ↓
Process Owner
        ↓
Configuration
        ↓
Accessible Resources
```

Example:

```text
Backup Software
        ↓
backup-agent.exe
        ↓
SYSTEM
        ↓
C:\ProgramData\Backup\
        ↓
Current user has Modify permission
```

This is significantly more interesting than simply discovering that backup software is installed.

---

## 8. Application Services

Applications often install Windows services.

Enumerate services:

```cmd
sc query state= all
```

PowerShell:

```powershell
Get-CimInstance Win32_Service |
Select-Object Name,DisplayName,State,StartName,PathName
```

For an individual service:

```cmd
sc qc <service>
```

Connect the service to the application:

```text
Application
    ↓
Service
    ↓
Executable
    ↓
Service Account
    ↓
Configuration
    ↓
Permissions
```

Review the service account carefully.

A service running as:

```text
LocalSystem
LocalService
NetworkService
Administrator
Custom account
Domain account
```

may have different privilege implications.

---

## 9. Application Configuration

Look for configuration files in the application's installation and data directories.

Common formats:

```text
.config
.ini
.xml
.json
.yaml
.yml
.conf
.txt
```

Potential configuration information includes:

```text
Database connections
Service endpoints
API configuration
Authentication settings
Logging configuration
Plugin paths
Temporary directories
Update mechanisms
Credential references
```

Review permissions:

```cmd
icacls "C:\Path\To\Config"
```

The key question is:

> Can an unprivileged user modify configuration that is later consumed by a privileged application?

---

## 10. Writable Application Directories

A writable application directory can be significant when the application executes files from that location with elevated privileges.

Check:

```cmd
icacls "C:\Path\To\Application"
```

Look for permissions granted to:

```text
Users
Authenticated Users
Everyone
Domain Users
The current user
```

Pay attention to:

```text
M
F
W
```

where applicable.

Do not assume that a writable directory automatically provides privilege escalation.

Determine:

1. What can be modified?
2. Which process uses it?
3. Under which account?
4. When is it loaded?
5. Is the modified resource actually executed?
6. Can this cross the privilege boundary?

---

## 11. DLL and Plugin Locations

Applications may load:

```text
DLLs
Plugins
Extensions
Modules
Drivers
Provider components
```

Investigate application-specific module directories.

Potentially relevant locations include:

```text
Application directory
Plugin directory
Extension directory
Configured module directory
Custom search paths
```

The important relationship is:

```text
Privileged application
        ↓
Loads component
        ↓
Component location is writable
        ↓
Current user can modify component
        ↓
Component is loaded with privileged context
```

Do not treat every DLL in an application directory as exploitable.

The loading behavior must be established first.

---

## 12. PATH and Search-Order Relationships

Applications may locate executables or libraries through configured search paths.

Review the system PATH:

```cmd
echo %PATH%
```

PowerShell:

```powershell
$env:Path
```

Identify directories that are:

* Writable by the current user
* Used by privileged processes
* Located before trusted directories
* Referenced by application configuration

A writable directory in PATH is not automatically a privilege-escalation vulnerability.

It becomes relevant when a privileged process actually searches that location for a required executable or component.

---

## 13. Application Updates

Applications may have automatic update mechanisms.

Investigate:

```text
Update service
Update executable
Update directory
Update configuration
Update account
Scheduled task
Updater permissions
```

Questions to answer:

```text
Who performs the update?
Which account runs the updater?
Can the current user modify updater files?
Can the current user modify update configuration?
Is the update mechanism integrity-protected?
```

The relationship to test is:

```text
Privileged updater
        ↓
Writable update resource
        ↓
Current user can modify resource
        ↓
Updater consumes resource
        ↓
Privilege boundary
```

---

## 14. Custom Applications

Custom or internally developed applications deserve additional attention because their security assumptions may differ from standard software.

Identify:

* Application owner
* Installation path
* Executables
* Services
* Configuration
* Databases
* Logs
* Scripts
* Scheduled tasks
* External dependencies
* Service accounts

Look for relationships such as:

```text
Custom application
        ↓
Runs as SYSTEM
        ↓
Reads configuration from ProgramData
        ↓
Configuration writable by Users
```

This creates a concrete configuration-to-privilege relationship worth validating.

---

## 15. Database Software

Database software may expose useful information about:

```text
Database service
Database account
Configuration
Connection strings
Backup locations
Database files
Service permissions
Application integrations
```

Identify whether the database is:

```text
Running
Locally accessible
Privileged
Used by another privileged application
Configured with exposed credentials
```

Do not assume database access automatically equals operating-system privilege escalation.

Determine the actual privilege boundary.

---

## 16. Web Servers

Web servers can be particularly important because they frequently interact with:

```text
Services
Application pools
Configuration files
Web applications
Databases
Scheduled jobs
Service accounts
Writable web directories
```

Map:

```text
Web Server
    ↓
Worker Process
    ↓
Process Account
    ↓
Application Files
    ↓
Configuration
    ↓
Writable Resources
```

The web server's process identity is especially important.

---

## 17. Security Software

Identify security-related software:

```text
Antivirus
EDR
Endpoint management
Monitoring agents
Backup agents
Remote administration tools
```

Do not assume that security software itself is an escalation opportunity.

Instead determine:

* Which services it installs
* Which accounts those services use
* Where configuration is stored
* Whether ordinary users can modify those resources
* Whether privileged components interact with user-controlled files

Security software should be handled carefully because unnecessary modification can disrupt the host.

---

## 18. Version Analysis

A version number can be useful, but:

> **Old does not automatically mean exploitable.**

When a potentially vulnerable version is identified, determine:

```text
Exact product
        ↓
Exact version
        ↓
Affected component
        ↓
Relevant vulnerability
        ↓
Required conditions
        ↓
Current configuration
        ↓
Privilege impact
```

Separate:

```text
Potentially vulnerable
```

from:

```text
Confirmed exploitable in this environment
```

If a vulnerability database or advisory is used, record the exact product and version rather than relying on a generic application name.

---

## 19. Patch and Update Context

Do not report software as vulnerable solely because its version appears old.

Check:

* Exact version
* Installed patches
* Vendor update status
* Operating-system architecture
* Relevant configuration
* Required privileges
* Exploit prerequisites
* Whether the vulnerable component is actually used

A vulnerable version may not create a privilege-escalation path if the affected functionality is disabled or inaccessible.

---

## 20. File Permissions and Application Risk

For each important application:

```text
Application
    ↓
Installation directory
    ↓
Executable
    ↓
Configuration
    ↓
Plugins / DLLs
    ↓
Logs / temporary files
    ↓
Update mechanism
```

Check permissions at each relevant point.

Example:

```cmd
icacls "C:\Program Files\Application"
icacls "C:\ProgramData\Application"
```

Then inspect specific files:

```cmd
icacls "C:\Program Files\Application\application.exe"
```

The goal is to find:

```text
Privileged execution
        +
User-controlled resource
        =
Potential escalation path
```

---

## 21. Application Dependency Map

Maintain a map for high-value applications:

```text
Application
    ↓
Executable
    ↓
Process
    ↓
Service / Task
    ↓
Account
    ↓
Configuration
    ↓
Dependencies
    ↓
Permissions
```

Example:

```text
Monitoring Agent
    ↓
monitor.exe
    ↓
Windows Service
    ↓
LocalSystem
    ↓
C:\ProgramData\Monitor\
    ↓
Config + plugin directory
    ↓
Users: Modify
```

This map gives you a concrete investigation path.

---

## 22. Common Findings

Potential findings include:

### Writable privileged application resource

```text
Privileged process
        ↓
Application file/configuration
        ↓
Current user can modify it
```

### Insecure updater

```text
Privileged updater
        ↓
User-writable update directory
```

### Exposed application credential

```text
Configuration
        ↓
Credential
        ↓
Higher-privileged account
```

### Vulnerable privileged component

```text
Installed component
        ↓
Affected version
        ↓
Applicable vulnerability
        ↓
Required conditions satisfied
```

### Misconfigured custom software

```text
Custom application
        ↓
Privileged execution
        ↓
Weak file/configuration permissions
```

---

## 23. Common False Positives

Avoid treating the following as confirmed escalation paths:

* Old software with no applicable vulnerability
* Installed software that is not running
* Writable application files that are never executed
* Writable directories unrelated to privileged execution
* User-level applications
* Outdated applications with mitigations already applied
* Vulnerabilities requiring conditions absent from the host
* Configuration values that cannot influence privileged execution
* Application credentials belonging to the current privilege level

Always connect the application finding to an actual security boundary.

---

## 24. Validation Workflow

Use this process:

```text
Application identified
        ↓
Determine version and location
        ↓
Determine execution context
        ↓
Map processes/services/tasks
        ↓
Inspect configuration
        ↓
Inspect permissions
        ↓
Identify user-controlled resources
        ↓
Determine privilege boundary
        ↓
Validate safely
        ↓
Document evidence
```

Validation should be minimally invasive.

Do not modify production software, services, configuration, or security controls unless explicitly authorized.

---

## 25. Finding Classification

### Observation

Software is installed.

```text
Application X
Version Y
```

### Lead

The application has a potentially relevant configuration, version, or permission issue.

```text
Application X
        ↓
Runs as SYSTEM
        ↓
ProgramData directory is writable
```

### Validated Finding

Authorized testing confirms that the weakness can cross the privilege boundary.

```text
Privileged application
        ↓
User-controlled resource
        ↓
Authorized validation
        ↓
Elevated execution confirmed
```

Keep these categories separate in notes and reports.

---

## 26. Application Enumeration Checklist

### Inventory

* [ ] Installed applications enumerated
* [ ] Versions recorded
* [ ] Installation paths identified
* [ ] Relevant applications prioritized
* [ ] Running applications identified

### Execution Context

* [ ] Processes mapped
* [ ] Process owners identified
* [ ] Services mapped
* [ ] Scheduled tasks mapped
* [ ] Privileged applications identified

### Configuration

* [ ] Configuration locations identified
* [ ] Relevant configuration reviewed
* [ ] Credentials/secrets considered
* [ ] Update mechanisms identified
* [ ] Plugin/DLL locations identified

### Permissions

* [ ] Application directories checked
* [ ] Executables checked
* [ ] Configuration files checked
* [ ] Plugin/DLL locations checked
* [ ] Update directories checked
* [ ] User-writable resources identified

### Vulnerability Analysis

* [ ] Exact versions recorded
* [ ] Applicable advisories considered
* [ ] Required conditions checked
* [ ] Current configuration considered
* [ ] False positives eliminated
* [ ] Privilege boundary established

### Validation

* [ ] Validation is authorized
* [ ] Validation is minimally invasive
* [ ] Evidence recorded
* [ ] Sensitive data protected
* [ ] Impact documented

---

## 27. What This Stage Should Produce

By the end of this stage, you should have:

```text
Installed Software Inventory
        ↓
Application Prioritization
        ↓
Execution Context
        ↓
Configuration Map
        ↓
Permission Analysis
        ↓
Version / Vulnerability Context
        ↓
Validated Privilege-Escalation Candidates
```

The important outcome is not a list of installed programs.

It is an understanding of **which software interacts with privileged execution and whether the current user can influence that execution**.

---

## Next Step

Continue to:

```text
12-Network-Enumeration/
```

The next stage will examine Windows network configuration, interfaces, routes, listening services, connections, firewall context, shares, and network relationships that may reveal privilege-escalation opportunities.
