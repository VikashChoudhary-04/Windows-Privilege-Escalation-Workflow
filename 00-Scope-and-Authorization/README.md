# Scope & Authorization

Before performing Windows privilege escalation enumeration or exploitation, establish what you are authorized to test and what actions are permitted.

Privilege escalation testing can affect system stability, services, accounts, files, and security controls. A clearly defined scope prevents accidental testing outside the authorized environment.

---

## 1. Confirm Authorization

Verify that you have explicit permission to perform security testing against the target.

Authorization may come from:

* Ownership of the system.
* A controlled personal lab.
* A cybersecurity training platform.
* A penetration-testing engagement.
* A documented security assessment.
* A written rules-of-engagement document.

Do not assume that access to a system means authorization to test it.

---

## 2. Identify the Target

Record the system or environment being tested.

Useful information includes:

| Item             | Example              |
| ---------------- | -------------------- |
| Target IP        | `192.168.56.101`     |
| Hostname         | `WIN-LAB`            |
| Operating System | Windows 11           |
| Environment      | Local VM             |
| Account          | `labuser`            |
| Assessment Type  | Privilege Escalation |
| Authorization    | Personal Lab         |

The exact information available will depend on the environment.

---

## 3. Define the Testing Boundary

Determine what is inside and outside the assessment scope.

### In Scope

Examples:

* The assigned Windows virtual machine.
* Specific user accounts.
* Local privilege escalation.
* Authorized enumeration.
* Authorized exploitation of identified weaknesses.

### Out of Scope

Examples:

* Other machines on the network.
* Unrelated user accounts.
* Production systems.
* External infrastructure.
* Data belonging to other users.
* Actions explicitly prohibited by the rules of engagement.

---

## 4. Establish the Starting Context

Before attempting privilege escalation, establish what access you already have.

Record:

* Current username.
* Current groups.
* Current privilege level.
* Integrity level where applicable.
* Interactive or non-interactive access.
* Local or remote access.
* Available shells.
* Available tools.

The starting context is important because privilege escalation is fundamentally about crossing a privilege boundary.

```text
Current Security Context
          │
          ▼
Identify Available Privileges
          │
          ▼
Enumerate Potential Weaknesses
          │
          ▼
Validate Privilege Boundary
          │
          ▼
Higher-Privilege Context
```

---

## 5. Define Rules of Engagement

Where applicable, establish:

* Permitted testing times.
* Permitted techniques.
* Permitted tools.
* Whether exploitation is allowed.
* Whether persistence is prohibited.
* Whether credential extraction is permitted.
* Whether security controls may be modified.
* Whether system changes must be reverted.
* Whether proof-of-concept execution is required.

For a personal laboratory, these rules can be defined by the lab owner.

---

## 6. Protect Sensitive Information

During enumeration, sensitive information may be encountered.

Examples include:

* Passwords.
* Authentication tokens.
* API keys.
* Private keys.
* Configuration secrets.
* Personal data.

Do not unnecessarily copy, expose, or publish sensitive information.

When documenting findings, record enough information to demonstrate the issue without exposing unrelated secrets.

---

## 7. Avoid Unnecessary Changes

Enumeration should generally begin with the least invasive actions possible.

Prefer:

```text
Read
 ↓
Analyze
 ↓
Validate
 ↓
Modify only when required
```

Avoid making unnecessary changes to:

* Services.
* Registry configuration.
* User accounts.
* Security settings.
* System files.
* Scheduled tasks.
* Network configuration.

If exploitation requires a modification, document the change and restore the original state when required by the engagement or lab.

---

## 8. Scope Checklist

Before starting the workflow:

```text
[ ] Authorization confirmed
[ ] Target identified
[ ] Testing boundary defined
[ ] Starting account identified
[ ] Current privilege level established
[ ] Allowed techniques understood
[ ] Exploitation permissions confirmed
[ ] Sensitive-data handling understood
[ ] Cleanup requirements understood
```

---

## 9. Engagement Notes

Maintain a basic record throughout the assessment.

```text
Target:
Hostname:
IP Address:
Operating System:
Starting User:
Starting Privilege:
Access Method:
Authorization:
Scope:
Notes:
```

These notes provide the context needed to understand findings later in the workflow.

---

## Next Step

Once authorization and scope are established, move to:

```text
01-Initial-Access-Context/
```

The next stage establishes exactly **what access you currently have before beginning systematic Windows enumeration**.
