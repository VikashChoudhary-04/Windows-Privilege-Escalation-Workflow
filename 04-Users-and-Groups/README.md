# Users & Groups

Windows privilege boundaries are heavily influenced by users, groups, and the permissions associated with them.

This stage identifies:

* Local users.
* Domain context.
* Local groups.
* Group memberships.
* Administrative relationships.
* Account configuration.
* Security-relevant group memberships.
* Relationships that may provide additional privileges.

The objective is to answer:

> **Who can access this system, what groups do they belong to, and what privileges or access can those relationships provide?**

---

## 1. Enumeration Objectives

Establish:

```text
Users
  ↓
Groups
  ↓
Memberships
  ↓
Privileges
  ↓
Access Relationships
  ↓
Potential Privilege Boundaries
```

Do not assume that a user or group with an interesting name is privileged.

Always verify the actual permissions and security context.

---

## 2. List Local Users

Start with:

```cmd
net user
```

Example:

```text
User accounts for \\WINLAB

------------------------------------------------
Administrator
Guest
student
svc_backup
```

Record accounts that appear relevant.

Potentially interesting accounts may include:

* Administrator.
* Service accounts.
* Backup-related accounts.
* Application-specific accounts.
* Accounts with unusual names.
* Accounts created outside the standard installation.

The username alone does not establish privilege.

---

## 3. Inspect the Current User

Review the current account:

```cmd
net user %USERNAME%
```

Useful information may include:

* Account active status.
* Password-related settings.
* Group memberships.
* Local group memberships.
* Last logon information.
* Account expiration.
* Password requirements.

Also use:

```cmd
whoami /user
```

and:

```cmd
whoami /groups
```

The objective is to correlate the account's configuration with its security token.

---

## 4. Inspect a Specific User

For an individual account:

```cmd
net user username
```

Example:

```cmd
net user svc_backup
```

Questions to ask:

```text
Is the account active?
Is it a service account?
Which groups is it a member of?
Does it have unusual account configuration?
Is it associated with a privileged role?
```

Do not attempt password changes or authentication against discovered accounts unless explicitly authorized.

---

## 5. Enumerate Local Groups

List local groups:

```cmd
net localgroup
```

This provides an overview of the groups defined on the system.

Important groups may include:

```text
Administrators
Users
Remote Desktop Users
Backup Operators
Remote Management Users
Network Configuration Operators
Power Users
Print Operators
Server Operators
```

The exact groups depend on the Windows edition and system configuration.

---

## 6. Inspect the Administrators Group

One of the first groups to inspect is:

```cmd
net localgroup Administrators
```

Record:

```text
Local members
Domain members
Service/application accounts
Unexpected accounts
```

Membership in the local Administrators group generally represents a significantly different security context from membership in the standard Users group.

However, the exact behavior of administrative access can be affected by UAC and the current access token.

---

## 7. Inspect Other Security-Relevant Groups

Enumerate potentially interesting groups individually.

Examples:

```cmd
net localgroup "Remote Desktop Users"
```

```cmd
net localgroup "Backup Operators"
```

```cmd
net localgroup "Remote Management Users"
```

```cmd
net localgroup "Network Configuration Operators"
```

```cmd
net localgroup "Server Operators"
```

The purpose is to determine:

```text
Which users?
      ↓
Which groups?
      ↓
What permissions does that group provide?
      ↓
Can those permissions affect a privileged resource?
```

Group membership should therefore be treated as an **access relationship**, not simply a label.

---

## 8. Enumerate Current Token Groups

The effective security token is more important than the account database alone.

Use:

```cmd
whoami /groups
```

This can reveal:

* User groups.
* Domain groups.
* Local groups.
* Integrity level.
* Group attributes.
* Enabled or deny-only group states.

Pay attention to the distinction between a group being present and a group being effectively enabled in the current token.

---

## 9. Understand Deny-Only Groups

A group can appear in the token without functioning like a normal enabled group.

For example, UAC can affect how administrative group membership appears in an access token.

Therefore:

```text
Group appears
     ≠
Group is currently providing unrestricted access
```

Always inspect the token output rather than relying only on:

```cmd
net localgroup Administrators
```

---

## 10. Domain Groups

If the system is domain-joined, inspect the user's domain context.

```cmd
whoami /groups
```

You may see domain groups associated with the account.

Where appropriate:

```cmd
whoami /upn
```

The exact information available depends on the account and domain configuration.

Domain membership can introduce additional access relationships, but domain-level investigation should remain within the authorized scope.

---

## 11. Inspect Group Membership Recursively

A user may receive access indirectly.

For example:

```text
User
  ↓
Group A
  ↓
Group B
  ↓
Privileged Resource
```

Therefore, ask:

```text
Is the user directly in the group?
Is the user indirectly receiving membership?
Does the group contain another privileged group?
What permissions does the resulting membership provide?
```

For domain environments, group nesting can become especially important.

---

## 12. Check Account Configuration

For the current user:

```cmd
net user %USERNAME%
```

Review relevant fields such as:

```text
Account active
Account expires
Password last set
Password expires
Password required
Local Group Memberships
Global Group Memberships
```

These fields provide context but should not be interpreted as vulnerabilities without additional evidence.

---

## 13. Check Other Local Accounts

Where authorized, inspect potentially relevant accounts:

```cmd
net user Administrator
```

```cmd
net user Guest
```

For application/service accounts:

```cmd
net user svc_account
```

The goal is to understand account roles and relationships.

Avoid unnecessary authentication attempts against discovered accounts.

---

## 14. Identify Service Accounts

Service accounts deserve particular attention because they may operate processes with elevated privileges.

A basic service-account relationship can be identified through:

```cmd
sc query
```

and:

```cmd
wmic service get Name,StartName
```

where WMIC is available.

PowerShell:

```powershell
Get-CimInstance Win32_Service |
Select-Object Name,StartName,State
```

This produces a useful relationship:

```text
Service
   ↓
Service Account
   ↓
Privilege Context
```

Detailed service analysis belongs in:

```text
06-Processes-and-Services/
```

---

## 15. Identify Special Group Memberships

Certain Windows groups can provide capabilities that deserve further investigation.

Examples include:

### Backup Operators

May have special backup/restore-related capabilities.

### Remote Desktop Users

Provides remote interactive-logon capability when the relevant system configuration permits it.

### Remote Management Users

May provide access to remote management mechanisms.

### Network Configuration Operators

May have additional network-configuration permissions.

### Server Operators

Can have additional system-management capabilities depending on the environment.

### Print Operators

May have additional printer-management capabilities and should be evaluated according to the specific Windows configuration.

The important question is always:

> **What concrete access does this membership provide on this system?**

---

## 16. Check SID Information

The current user's SID:

```cmd
whoami /user
```

Group SIDs can be observed through:

```cmd
whoami /groups
```

SIDs are useful when:

* Identifying accounts.
* Correlating registry ACLs.
* Understanding filesystem ACLs.
* Analyzing security descriptors.
* Distinguishing local and domain identities.

A SID is an identity identifier, not a privilege by itself.

---

## 17. Local vs Domain Identity

Build a distinction between:

```text
Local Identity
    │
    ├── Local user
    └── Local group

Domain Identity
    │
    ├── Domain user
    └── Domain group
```

Then determine which identity is actually present in the current token.

This becomes increasingly important when examining:

* File permissions.
* Services.
* Scheduled tasks.
* Registry permissions.
* Network resources.
* Domain-related access.

---

## 18. Group-to-Privilege Reasoning

Use this reasoning model:

```text
User
 ↓
Group Membership
 ↓
Effective Token
 ↓
Assigned Rights
 ↓
Accessible Resource
 ↓
Potential Privilege Boundary
```

Example:

```text
User
 ↓
Backup Operators
 ↓
Backup/Restore-related rights
 ↓
Access to protected data/resources
 ↓
Investigate exact permissions
 ↓
Determine whether privilege escalation is possible
```

Do not skip the middle steps.

A group name alone is not sufficient evidence.

---

## 19. Interesting Finding vs Confirmed Path

Use three categories:

### Observation

Something unusual was discovered.

```text
User belongs to an unusual group.
```

### Lead

The observation may affect privilege boundaries.

```text
Group provides special operating-system rights.
```

### Confirmed Path

The rights can be used under the current conditions to cross a privilege boundary.

```text
Current user
    ↓
Special privilege
    ↓
Accessible privileged resource
    ↓
Validated privilege escalation
```

This distinction will be used throughout the repository.

---

## 20. Build the Identity Map

Create a simple map of the environment.

```text
IDENTITY MAP
------------

Current User:
SID:

Local Groups:
    Administrators:
    Users:
    Remote Desktop Users:
    Other:

Current Token Groups:

Domain:
Workgroup:

Interesting Accounts:

Interesting Service Accounts:

Potential Privileged Relationships:
```

This becomes the identity baseline for later privilege and token analysis.

---

## 21. Users & Groups Checklist

```text
[ ] Local users enumerated
[ ] Current user inspected
[ ] Current SID identified
[ ] Local groups enumerated
[ ] Administrators group inspected
[ ] Security-relevant groups inspected
[ ] Current token groups inspected
[ ] Deny-only groups understood where applicable
[ ] Domain context identified
[ ] Domain group memberships reviewed where applicable
[ ] Account configuration reviewed
[ ] Service accounts identified
[ ] Interesting group relationships documented
[ ] Local/domain identities distinguished
[ ] Identity map created
[ ] Potential privilege paths documented
```

---

## 22. Decision Point

After completing user and group enumeration:

```text
                  Users & Groups
                        │
          ┌─────────────┼─────────────┐
          │             │             │
          ▼             ▼             ▼
    Admin Group    Special Group   Token Groups
          │             │             │
          ▼             ▼             ▼
      Examine        Examine       Examine
      privileges     access        effective
                                    context
          │             │             │
          └─────────────┼─────────────┘
                        ▼
              Privilege Enumeration
```

If a group provides interesting rights, continue into privilege analysis rather than attempting exploitation immediately.

---

## Next Step

Proceed to:

```text
05-Privileges-and-Access-Tokens/
```

The next stage focuses on the **Windows security token** itself:

* Assigned privileges.
* Enabled and disabled privileges.
* Integrity levels.
* Token types.
* Impersonation.
* Security identifiers.
* Privilege-related escalation opportunities.

The central question becomes:

> **What can the current security token actually do, and does it contain a privilege that can cross the current security boundary?**
