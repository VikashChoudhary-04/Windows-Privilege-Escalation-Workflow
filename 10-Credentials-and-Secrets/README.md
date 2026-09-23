# Credentials and Secrets

Credentials and secrets are frequently exposed through Windows configuration, application files, scripts, environment variables, registry entries, and stored authentication material.

The goal of this stage is **not to blindly dump credentials**. The goal is to identify credential exposure that could cross a privilege boundary, determine whether the discovered secret is actually usable, and validate the finding safely within the authorized environment.

---

## 1. Objective

At this stage, determine:

* Where credentials or secrets may be stored
* Which accounts those credentials belong to
* Whether the credentials are plaintext, encoded, hashed, or otherwise protected
* Whether the current user can access the storage location
* Whether the credential provides access to a higher-privileged account or resource
* Whether the discovered secret is still valid
* Whether the secret can actually cross a privilege boundary

The key question is:

> **Can accessible credential material provide higher privileges than the current security context?**

---

## 2. Credential Discovery Mindset

Do not begin by searching every file on the system.

Start with locations that are relevant to the current host and the findings from previous stages.

Useful sources include:

```text
Configuration files
Application files
Scripts
Environment variables
Registry
Scheduled task definitions
Service configurations
Deployment files
Backup files
Log files
User profile data
Temporary files
Command histories
Windows Credential Manager
Application-specific credential stores
```

Build on the enumeration already performed.

For example:

```text
Privileged service
        ↓
Custom service configuration
        ↓
Configuration file
        ↓
Stored credential
        ↓
Account with additional privileges
```

This creates a much stronger lead than randomly searching the entire filesystem.

---

## 3. Environment Variables

Environment variables may contain configuration information, paths, tokens, or occasionally credentials.

Review the current environment:

```cmd
set
```

PowerShell:

```powershell
Get-ChildItem Env:
```

Pay particular attention to variables related to:

```text
PASSWORD
PASS
SECRET
TOKEN
KEY
API
AUTH
USER
USERNAME
CONNECTION
DATABASE
```

A suspicious variable is only a lead.

Determine:

1. Who can read it?
2. Which process sets it?
3. When is it created?
4. What resource uses it?
5. Does it contain an actual secret?
6. What account does the secret belong to?

---

## 4. Configuration Files

Applications frequently store configuration in files such as:

```text
.config
.ini
.xml
.json
.yaml
.yml
.txt
.ps1
.bat
.cmd
```

Look for application-specific configuration locations rather than immediately scanning the entire disk.

Examples:

```text
C:\ProgramData\
C:\Program Files\
C:\Program Files (x86)\
C:\Users\<user>\AppData\
Application installation directories
Application data directories
Service-specific directories
```

Search for relevant keywords when appropriate:

```cmd
findstr /spin "password" C:\Path\*.config
findstr /spin "password" C:\Path\*.xml
findstr /spin "secret" C:\Path\*.json
findstr /spin "token" C:\Path\*.config
```

Use targeted searches.

Avoid indiscriminate searches across large system directories because they can produce excessive noise and may expose unrelated sensitive information.

---

## 5. Scripts

Scripts deserve particular attention because administrators and applications sometimes embed credentials directly into automation.

Relevant locations may include:

```text
Scheduled task directories
Application directories
Administrative scripts
Deployment directories
Backup scripts
Maintenance scripts
User profile directories
ProgramData
```

Potential indicators include:

```text
$password
ConvertTo-SecureString
PSCredential
net use
runas
connection strings
API keys
authentication headers
service credentials
database credentials
```

A script containing a credential is not automatically exploitable.

Determine:

```text
Who can read the script?
        ↓
What account does the credential belong to?
        ↓
Is the credential still valid?
        ↓
What can that account access?
        ↓
Does that access cross the privilege boundary?
```

---

## 6. Registry Credential Exposure

The registry may contain application configuration and, in some cases, credentials or secrets.

Review application-specific locations discovered during registry enumeration:

```cmd
reg query HKLM\SOFTWARE
reg query HKCU\SOFTWARE
```

For 32-bit applications on a 64-bit system:

```cmd
reg query HKLM\SOFTWARE\WOW6432Node
```

Pay particular attention to:

```text
Database configuration
Application authentication
Service configuration
Deployment configuration
Software-specific credential storage
Connection strings
API configuration
```

Do not assume that a value containing words such as `Password` or `Secret` is plaintext or usable.

Determine how the application actually consumes the value.

---

## 7. Service Credentials

Services may run under accounts other than the current user.

Enumerate service configuration:

```cmd
sc query state= all
```

Inspect individual services:

```cmd
sc qc <service>
```

PowerShell:

```powershell
Get-CimInstance Win32_Service |
    Select-Object Name, StartName, State, PathName
```

Pay attention to:

```text
StartName
Binary path
Configuration files
Service-specific directories
Service arguments
```

If a service uses a custom account, investigate whether credential material is exposed elsewhere.

The important relationship is:

```text
Service
   ↓
Service account
   ↓
Account privileges
   ↓
Credential exposure
   ↓
Potential privilege boundary
```

---

## 8. Scheduled Task Credentials

Scheduled tasks may execute under privileged accounts.

Review:

```cmd
schtasks /query /fo LIST /v
```

PowerShell:

```powershell
Get-ScheduledTask
```

Identify:

* Task name
* Principal
* Run-as account
* Actions
* Executables
* Scripts
* Arguments
* Task location
* Trigger
* File permissions

Do not assume that discovering a privileged task means its credentials are exposed.

Instead ask:

> Can the current user access or modify something used by that privileged task?

This connects credential analysis with the earlier **Scheduled Tasks** and **Filesystem and Permissions** stages.

---

## 9. Windows Credential Manager

Windows can store credentials through Credential Manager.

Basic command:

```cmd
cmdkey /list
```

This can reveal stored credential targets available to the current context.

Treat the output as information about credential storage rather than automatically assuming the credentials can be extracted or reused.

Document:

```text
Target
Credential type
Current user context
Associated resource
Potential privilege level
```

---

## 10. User Profile Data

Review relevant user-profile locations:

```text
C:\Users\<user>\
C:\Users\<user>\AppData\Local\
C:\Users\<user>\AppData\Roaming\
```

Applications may store:

```text
Configuration
Tokens
Session information
Connection details
Application databases
History
Logs
Backup files
```

Focus on applications installed or identified during earlier enumeration.

Avoid treating every application file as a credential source.

---

## 11. Command History and Administrative Artifacts

Administrative commands can sometimes expose secrets through arguments or scripts.

Look for relevant history or automation artifacts where applicable.

Examples of interesting patterns include:

```text
password arguments
connection strings
authentication tokens
API keys
service account names
database credentials
remote connection commands
```

Remember:

> A secret appearing in command history may indicate credential exposure, but its presence does not prove that it is still valid.

---

## 12. Application Data

Installed applications should be investigated according to their role.

Examples:

```text
Web servers
Database servers
Development tools
Backup software
Monitoring software
Remote administration software
Deployment systems
Custom enterprise applications
```

For each relevant application determine:

```text
Where is it installed?
        ↓
Which account runs it?
        ↓
Where is its configuration?
        ↓
Who can read the configuration?
        ↓
Does it store credentials or tokens?
        ↓
What resources can those credentials access?
```

Application-specific knowledge is often more useful than generic credential hunting.

---

## 13. Backup and Temporary Files

Backups and temporary artifacts can contain older configuration.

Potential locations include:

```text
Backup directories
Temporary directories
Application backup files
Old configuration files
`.bak`
`.old`
`.backup`
`.tmp`
```

Example targeted search:

```cmd
dir /s /b C:\Path\*.bak
dir /s /b C:\Path\*.old
dir /s /b C:\Path\*.config
```

An old credential may be:

* Expired
* Disabled
* Rotated
* Replaced
* Restricted to a specific system

Therefore, validate before treating it as a finding.

---

## 14. Search Strategy

Use a targeted approach.

### Phase 1 — Identify Relevant Applications

From previous enumeration:

```text
Installed software
        ↓
Running processes
        ↓
Services
        ↓
Scheduled tasks
        ↓
Configuration locations
```

### Phase 2 — Identify Configuration Locations

```text
Program Files
ProgramData
User AppData
Service directories
Application directories
Registry
```

### Phase 3 — Search Relevant Artifacts

Search for:

```text
password
passwd
pwd
secret
token
apikey
api_key
connectionstring
credential
```

### Phase 4 — Understand the Secret

Determine:

```text
What is it?
Who owns it?
What does it authenticate to?
Is it protected?
Is it still valid?
```

### Phase 5 — Determine Privilege Impact

Ask:

```text
Does the account have more privileges than the current user?
Can the account access a privileged service?
Can it access sensitive files?
Can it administer the host?
Can it cross the current privilege boundary?
```

---

## 15. Credential Types

Not all credential material has the same value.

| Type                   | Example                     | Initial Question                                 |
| ---------------------- | --------------------------- | ------------------------------------------------ |
| Plaintext password     | `Password=...`              | Is it valid and privileged?                      |
| Hash                   | NTLM-style hash             | What authentication context does it represent?   |
| Token                  | API/session token           | What resource accepts it?                        |
| Connection string      | Database credentials        | What database/account does it access?            |
| API key                | Application key             | What permissions does it provide?                |
| Stored credential      | Credential Manager entry    | What resource is associated with it?             |
| Encrypted secret       | Protected application data  | Can the intended application/context decrypt it? |
| Configuration username | Service/application account | Is the corresponding secret exposed elsewhere?   |

The presence of a secret is only the beginning of the analysis.

---

## 16. Privilege-Boundary Reasoning

Use this model:

```text
Credential discovered
        ↓
Identify owner
        ↓
Identify authentication target
        ↓
Determine permissions
        ↓
Compare with current context
        ↓
Validate authorized access
        ↓
Determine privilege impact
```

Example:

```text
Current user
    ↓
Reads application configuration
    ↓
Finds service account credential
    ↓
Service account belongs to privileged group
    ↓
Credential is still valid
    ↓
Authorized validation confirms additional access
```

This is a meaningful privilege-escalation path.

By contrast:

```text
Password found
    ↓
Account disabled
```

or:

```text
Token found
    ↓
Token expired
```

or:

```text
Credential found
    ↓
Account has the same privileges as current user
```

does not establish a privilege-escalation path.

---

## 17. False Positives

Common false positives include:

* Example passwords in documentation
* Default credentials that have been changed
* Expired credentials
* Disabled accounts
* Test credentials with no useful permissions
* Encoded data mistaken for plaintext
* Encrypted secrets that cannot be used in the current context
* Application configuration that does not provide authentication
* Credentials belonging to low-privileged accounts
* Historical backup data
* Public or intentionally exposed application configuration

Always validate the security impact.

---

## 18. Sensitive Data Handling

Credential enumeration can expose highly sensitive information.

Follow these rules:

* Do not unnecessarily copy credentials.
* Do not publish real secrets in reports.
* Do not commit credentials to GitHub.
* Do not send discovered secrets to unauthorized parties.
* Record only the minimum evidence required.
* Redact secrets in screenshots and notes.
* Store assessment artifacts securely.
* Remove temporary copies after the assessment when permitted.

Example:

```text
Username: svc-backup
Password: [REDACTED]
Source: C:\ProgramData\Backup\config.xml
Impact: Account has elevated local privileges
```

---

## 19. Finding Classification

Classify observations before reporting them.

### Observation

Credential-like data exists.

```text
password=********
```

### Lead

The credential appears associated with a potentially privileged account.

```text
svc-admin
```

### Validated Finding

Authorized testing confirms that the credential provides additional privileges or access.

```text
svc-admin → elevated local privileges
```

This distinction prevents weak evidence from being reported as a confirmed vulnerability.

---

## 20. Credential Exposure Map

Maintain a simple map during the assessment:

```text
Credential Source
        ↓
Credential Type
        ↓
Account / Identity
        ↓
Authentication Target
        ↓
Privileges / Access
        ↓
Validation Status
        ↓
Impact
```

Example:

```text
Application config
        ↓
Service credential
        ↓
svc-backup
        ↓
Local service
        ↓
Backup Operators
        ↓
Validated
        ↓
Potential privilege boundary
```

---

## 21. Decision Tree

```text
Credential or secret discovered
            |
            v
Is it actually sensitive?
       /           \
     No             Yes
     |               |
   Ignore       Identify owner
                     |
                     v
             Is it accessible?
                /        \
              No          Yes
              |            |
          Document     Identify target
                           |
                           v
                   Is it still valid?
                     /          \
                   No            Yes
                   |              |
               Document      Determine access
                                  |
                                  v
                         Does it increase privilege?
                            /              \
                          No                Yes
                          |                  |
                       Document          Validate safely
                                             |
                                             v
                                       Record evidence
```

---

## 22. Credential Enumeration Checklist

### Identity

* [ ] Current user identified
* [ ] Account context identified
* [ ] Local/domain context understood
* [ ] Relevant privileged accounts identified

### Sources

* [ ] Environment variables reviewed
* [ ] Relevant configuration files reviewed
* [ ] Scripts reviewed
* [ ] Service configurations reviewed
* [ ] Scheduled tasks reviewed
* [ ] Registry locations reviewed
* [ ] Credential Manager reviewed
* [ ] Relevant application data reviewed
* [ ] Backup/configuration artifacts reviewed

### Analysis

* [ ] Credential owner identified
* [ ] Authentication target identified
* [ ] Credential type identified
* [ ] Access permissions understood
* [ ] Validity assessed
* [ ] Privilege level compared with current user
* [ ] False positives eliminated

### Validation

* [ ] Validation is authorized
* [ ] Validation is minimally invasive
* [ ] Sensitive information is protected
* [ ] Evidence is recorded
* [ ] Impact is documented

---

## 23. What This Stage Should Produce

By the end of this stage, you should have:

```text
Credential Sources
        ↓
Credential Inventory
        ↓
Account Mapping
        ↓
Access Analysis
        ↓
Validated Leads
        ↓
Privilege-Escalation Candidates
```

Do not move forward simply because a password or token was discovered.

Move forward when you understand **what the credential represents and whether it creates a meaningful privilege boundary**.

---

## Next Step

Continue to:

```text
11-Applications-and-Installed-Software/
```

The next stage maps installed applications and software components to their configuration, versions, execution context, permissions, and potential privilege-escalation relevance.
