# Reporting and Cleanup

A privilege-escalation assessment is not complete when elevated access is obtained.

The final stage converts the technical investigation into a clear finding, preserves the necessary evidence, documents impact and remediation, and verifies that temporary testing changes have been removed.

The final workflow is:

```text id="8c4m7q"
Finding
   ↓
Root Cause
   ↓
Evidence
   ↓
Impact
   ↓
Reproduction Conditions
   ↓
Remediation
   ↓
Cleanup
   ↓
Verification
   ↓
Final Report
```

The objective is to leave behind **useful evidence and actionable information, not unnecessary artifacts**.

---

## 1. Objective

At the end of the assessment:

* Consolidate validated findings
* Separate confirmed findings from observations
* Document the root cause
* Record affected resources
* Document the privilege boundary crossed
* Preserve appropriate evidence
* Explain reproduction conditions
* Provide remediation guidance
* Record cleanup actions
* Verify the final system state
* Capture lessons learned

---

## 2. Finding Lifecycle

Use a consistent lifecycle:

```text id="7v3n5m"
Observation
    ↓
Candidate
    ↓
Validated
    ↓
Exploited (if authorized)
    ↓
Documented
    ↓
Remediated / Recommended
    ↓
Closed
```

Not every observation becomes a finding.

Only report a privilege-escalation vulnerability as confirmed when the evidence supports it.

---

## 3. Finding Classification

Use clear classifications.

### Observation

An interesting configuration was discovered.

Example:

```text id="g5r2x8"
Service runs as SYSTEM.
```

### Candidate

A possible weakness was identified.

```text id="m7q3v1"
Service executable directory appears writable.
```

### Validated Finding

The complete privilege boundary was demonstrated.

```text id="k4n8p2"
Current user can influence a SYSTEM service resource,
resulting in execution under SYSTEM.
```

### False Positive

The initial assumption was incorrect.

```text id="r6x2m5"
Directory appeared writable but effective permissions
prevent modification by the current user.
```

This distinction keeps reports technically accurate.

---

# 4. Finding Structure

Each confirmed finding should contain:

```text id="x8m4q7"
Title
Severity / Risk Context
Affected Host
Affected Resource
Current Security Context
Root Cause
Technical Description
Attack Path
Evidence
Impact
Reproduction Conditions
Remediation
Validation Status
Cleanup Status
References
```

The exact format can be adapted to the assessment requirements.

---

# 5. Finding Title

Use a title that describes the actual weakness.

Good examples:

```text id="j4r8m2"
User-Writable Resource Used by Privileged Windows Service
Weak Permissions on Privileged Scheduled Task Resource
Writable Registry Configuration Used by SYSTEM Service
Exposed Privileged Service Credential
Insecure Application Update Configuration
```

Avoid vague titles such as:

```text id="b7q3n5"
Windows Vulnerability
Privilege Escalation Issue
Security Problem
```

The title should communicate the root cause.

---

# 6. Root Cause

Describe **why** the privilege boundary exists.

Examples:

```text id="v5m8r2"
The SYSTEM service executes an application binary
stored in a directory writable by standard users.
```

or:

```text id="n3q7x4"
A scheduled task executes a script under a privileged
account while the script is writable by the current user.
```

Root cause is more valuable than simply describing the exploitation technique.

---

# 7. Attack Path

Show the complete relationship:

```text id="c8r2m5"
Current User
      ↓
Writable Resource
      ↓
Privileged Consumer
      ↓
Trigger
      ↓
Elevated Execution
      ↓
SYSTEM / Administrator / Other Privileged Context
```

Example:

```text id="f6m3q9"
standard-user
      ↓
C:\ProgramData\App\service.exe
      ↓
Writable by standard-user
      ↓
ExampleService
      ↓
Runs as SYSTEM
      ↓
Authorized service trigger
      ↓
SYSTEM execution
```

This makes the finding easy to understand.

---

# 8. Evidence

Evidence should prove the individual steps of the attack path.

Useful evidence may include:

```text id="w2x7m4"
whoami
whoami /user
whoami /groups
whoami /priv
sc qc <service>
sc sdshow <service>
icacls <resource>
schtasks /query
reg query <key>
Process information
Before/after identity
```

Do not collect more sensitive information than necessary.

---

# 9. Evidence Standard

A strong finding should answer:

```text id="q9m4v6"
What was accessible?
        ↓
Who could control it?
        ↓
What privileged component consumed it?
        ↓
How was it triggered?
        ↓
Under which account did it execute?
        ↓
What privilege was obtained?
```

If one of these questions cannot be answered, the finding may need additional validation.

---

# 10. Sensitive Evidence

Never include unnecessary secrets in the final report.

Redact:

```text id="n5r8x2"
Passwords
API keys
Session tokens
Private keys
Authentication cookies
Personal data
Unrelated credentials
```

Use:

```text id="m7q2v4"
Password: [REDACTED]
Token: [REDACTED]
API Key: [REDACTED]
```

Record the source and impact without exposing the actual secret.

---

# 11. Impact

Impact should describe what the attacker could actually achieve.

Examples:

```text id="r4x8m1"
Local standard user → Administrator
```

or:

```text id="k6q3v9"
Local standard user → SYSTEM
```

or:

```text id="p8m2x5"
Unprivileged account → Privileged service account
```

Explain the consequence:

```text id="w3n7q4"
The weakness allows an authenticated local user to
influence a privileged Windows service and execute
code under the service's SYSTEM security context.
```

Do not exaggerate beyond the demonstrated result.

---

# 12. Reproduction Conditions

Document the conditions required for the finding.

For example:

```text id="x5m8q2"
1. Local user account exists.
2. User can modify the service resource.
3. Service runs as SYSTEM.
4. Service consumes the modified resource.
5. User can trigger the service operation.
```

This helps another tester reproduce the finding and helps defenders understand what must be fixed.

---

# 13. Reproduction Steps

Keep reproduction steps focused on the vulnerability.

Example structure:

```text id="v4q7m3"
1. Identify the current user.
2. Identify the affected service.
3. Verify the service execution account.
4. Verify permissions on the service resource.
5. Establish that the current user can control the resource.
6. Trigger the authorized validation mechanism.
7. Verify the resulting process identity.
8. Record evidence.
9. Restore the original state.
```

Do not include unnecessary attack activity.

---

# 14. Remediation

Remediation should address the root cause.

Examples:

### Writable Service Resource

```text id="c6r2n8"
Restrict write permissions on the service executable
and its parent directories to trusted administrators
and required service-management accounts.
```

### Writable Scheduled Task Script

```text id="x3m7q5"
Restrict modification of the scheduled task's executable
or script to authorized administrators.
```

### Weak Registry Permissions

```text id="n8q4v2"
Restrict write permissions on security-sensitive registry
keys and values.
```

### Exposed Credential

```text id="r5m3x7"
Remove plaintext credential storage, rotate the exposed
credential, and use an appropriate protected credential
storage mechanism.
```

### Insecure Application Configuration

```text id="q7v2m9"
Restrict configuration modification and ensure privileged
applications consume configuration only from trusted locations.
```

---

# 15. Defense-in-Depth Recommendations

Where appropriate, recommend:

* Least-privilege service accounts
* Strong filesystem permissions
* Restricted service-management permissions
* Protected registry configuration
* Secure credential storage
* Application allowlisting
* Regular patching
* Application inventory
* Monitoring of privileged services
* Controlled scheduled-task permissions
* Removal of unnecessary software
* Appropriate Windows security controls

Recommendations should address the observed risk rather than becoming a generic security checklist.

---

# 16. Cleanup Record

Record every temporary change made during validation.

Example:

```text id="m4x8q2"
Test Artifact:
C:\Temp\validation-test.ps1

Purpose:
Demonstrate privileged execution

Created:
[Timestamp]

Removed:
[Timestamp]

Verification:
File no longer present
```

For configuration changes:

```text id="v7q3n5"
Resource:
ExampleService

Original State:
Configuration A

Temporary State:
Configuration B

Restored:
Yes

Verification:
Service configuration matches original state
```

---

# 17. Cleanup Verification

Do not mark cleanup complete simply because the test command finished.

Verify:

```text id="k8r2m6"
Files
Directories
Services
Scheduled Tasks
Registry
Users
Groups
Processes
Permissions
Configuration
Startup entries
```

The final state should match the expected post-assessment state.

---

# 18. Temporary Accounts

If temporary accounts were explicitly authorized for testing:

```text id="p5m8r3"
Record account name
Record purpose
Record creation time
Record removal time
Verify account removal
```

Check:

```cmd id="x4q7m2"
net user
```

Do not leave test accounts active after the engagement unless explicitly required.

---

# 19. Temporary Services and Tasks

If testing created temporary services or tasks:

Verify that they have been removed.

Services:

```cmd id="r3n6v8"
sc query state= all
```

Tasks:

```cmd id="m7q2x4"
schtasks /query
```

Compare against the original inventory.

---

# 20. Final System State

Perform a final sanity check.

Review:

```text id="c8m4q7"
Current user
Running processes
Services
Scheduled tasks
Startup configuration
Modified files
Registry changes
Network listeners
Temporary artifacts
```

The objective is not to repeat the entire enumeration process.

The objective is to confirm that the testing process did not leave unintended changes.

---

# 21. Finding Quality Review

Before finalizing a finding, ask:

```text id="w5x8m2"
Is the root cause clear?
Is the affected resource identified?
Is user control proven?
Is privileged execution proven?
Is the attack path reproducible?
Is impact accurately described?
Is evidence sufficient?
Are secrets redacted?
Is remediation practical?
Is cleanup verified?
```

If any critical answer is no, improve the finding before finalizing it.

---

# 22. Report-Ready Finding Template

Use this structure for confirmed findings:

````markdown
## Finding: <Title>

### Summary

<Short description of the weakness and its security impact.>

### Affected Resource

- Host:
- Service/Application:
- File/Registry Key:
- Account:

### Root Cause

<Explain the configuration weakness.>

### Attack Path

```text
Current User
    ↓
Weak Resource
    ↓
Privileged Consumer
    ↓
Trigger
    ↓
Elevated Context
````

### Evidence

<Relevant commands and observations.>

### Reproduction Conditions

1. <Condition>
2. <Condition>
3. <Condition>

### Impact

<Describe the privilege boundary crossed.>

### Remediation

<Explain how to correct the root cause.>

### Validation Status

Validated / Exploited / Not Exploitable

### Cleanup Status

Complete / Requires Review

### References

<Relevant vendor, Microsoft, or security references.>

````

---

# 23. Assessment Summary

At the end of the engagement, summarize:

```text id="j4q8m2"
Hosts Assessed:
Initial User Context:
Confirmed Findings:
Potential Findings:
False Positives:
Privilege Boundaries Tested:
Authorized Exploitation Performed:
Cleanup Status:
Outstanding Items:
````

Keep the summary factual.

---

# 24. Lessons Learned

Record what the assessment demonstrated.

Examples:

```text id="x7m3r5"
Enumeration identified a SYSTEM service with a
user-writable resource.

Credential analysis identified a privileged service
account exposed through application configuration.

Scheduled-task enumeration identified a privileged
task consuming a user-controlled script.
```

The purpose is to improve future assessments.

---

# 25. Workflow Completion Checklist

### Scope

* [ ] Scope confirmed
* [ ] Authorization confirmed
* [ ] Target documented

### Enumeration

* [ ] Initial context documented
* [ ] System enumerated
* [ ] Users/groups enumerated
* [ ] Privileges/tokens analyzed
* [ ] Processes/services analyzed
* [ ] Scheduled tasks analyzed
* [ ] Filesystem permissions analyzed
* [ ] Registry analyzed
* [ ] Credentials/secrets analyzed
* [ ] Applications analyzed
* [ ] Network configuration analyzed

### Analysis

* [ ] Misconfigurations correlated
* [ ] Candidates documented
* [ ] False positives eliminated
* [ ] Privilege boundaries identified

### Validation

* [ ] Required conditions verified
* [ ] Authorized validation performed
* [ ] Execution context confirmed
* [ ] Impact confirmed
* [ ] Evidence captured

### Reporting

* [ ] Root cause documented
* [ ] Attack path documented
* [ ] Impact documented
* [ ] Reproduction conditions documented
* [ ] Remediation documented
* [ ] Sensitive information redacted

### Cleanup

* [ ] Temporary files removed
* [ ] Temporary scripts removed
* [ ] Services restored
* [ ] Scheduled tasks restored
* [ ] Registry restored
* [ ] Permissions restored
* [ ] Temporary accounts removed
* [ ] Temporary processes stopped
* [ ] Persistence checks completed
* [ ] Final state verified

---

# 26. Complete Workflow

The complete Windows privilege-escalation workflow is:

```text
00 Scope & Authorization
        ↓
01 Initial Access Context
        ↓
02 First 5 Minutes
        ↓
03 System Enumeration
        ↓
04 Users & Groups
        ↓
05 Privileges & Access Tokens
        ↓
06 Processes & Services
        ↓
07 Scheduled Tasks
        ↓
08 Filesystem & Permissions
        ↓
09 Registry
        ↓
10 Credentials & Secrets
        ↓
11 Applications & Installed Software
        ↓
12 Network Enumeration
        ↓
13 Windows Misconfigurations
        ↓
14 Validation & Exploitation
        ↓
15 Post-Exploitation Verification
        ↓
16 Reporting & Cleanup
```

The workflow can be summarized as:

```text
Enumerate
   ↓
Understand
   ↓
Correlate
   ↓
Identify
   ↓
Validate
   ↓
Exploit — Only When Authorized
   ↓
Verify
   ↓
Clean Up
   ↓
Document
```

---

# 27. Final Principle

The purpose of a privilege-escalation workflow is not to memorize the largest number of commands or exploitation techniques.

It is to understand the relationship between:

```text
Identity
    +
Permissions
    +
Privileged Processes
    +
Configuration
    +
Execution
    +
Security Boundaries
```

A strong assessment should allow you to explain:

> **What the current user can control, what privileged component consumes that control, why the configuration permits it, how the privilege boundary was crossed, what evidence proves it, and how the underlying weakness can be fixed.**

That reasoning is the foundation of practical Windows privilege-escalation assessment.
