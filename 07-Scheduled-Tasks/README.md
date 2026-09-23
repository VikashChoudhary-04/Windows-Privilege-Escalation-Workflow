# Scheduled Tasks

Windows Task Scheduler provides a mechanism for executing programs, scripts, and commands automatically according to defined triggers and conditions.

Scheduled tasks can become relevant to privilege escalation when a task executes with a higher-privileged security context while relying on resources that a lower-privileged user can modify.

The objective of this stage is to answer:

> **Which scheduled tasks execute with elevated privileges, what do they execute, when do they execute, and can the current user influence their execution path?**

---

## 1. Investigation Model

Use the following model:

```text
Scheduled Task
      ↓
Principal / Run-As Account
      ↓
Trigger
      ↓
Action
      ↓
Executable / Script
      ↓
Arguments / Working Directory
      ↓
File & Directory Permissions
      ↓
Task Permissions
      ↓
Can Current User Influence Execution?
      ↓
Potential Privilege Boundary
```

A task running as `SYSTEM` is not automatically vulnerable.

The complete execution chain must be established.

---

## 2. Enumerate Scheduled Tasks

Start with:

```cmd
schtasks /query
```

For detailed information:

```cmd
schtasks /query /fo LIST /v
```

Useful fields include:

```text
TaskName
Run As User
Task To Run
Schedule
Next Run Time
Status
```

Record tasks that appear relevant.

---

## 3. PowerShell Enumeration

PowerShell provides additional task information.

List tasks:

```powershell
Get-ScheduledTask
```

Display useful properties:

```powershell
Get-ScheduledTask |
Select-Object TaskName,TaskPath,State
```

Retrieve task information:

```powershell
Get-ScheduledTaskInfo -TaskName "<TaskName>"
```

For a specific task:

```powershell
Get-ScheduledTask -TaskName "<TaskName>"
```

---

## 4. Identify the Task Principal

The principal determines the security context under which the task runs.

Inspect:

```powershell
(Get-ScheduledTask -TaskName "<TaskName>").Principal
```

Important information can include:

* User or service account.
* Run level.
* Logon type.
* Group-related configuration.
* Whether elevated execution is requested.

Conceptually:

```text
Task
 ↓
Principal
 ↓
Security Context
```

---

## 5. Identify High-Privilege Tasks

Look for tasks executing as:

```text
SYSTEM
LOCAL SERVICE
NETWORK SERVICE
Administrator
Privileged service accounts
```

The important relationship is:

```text
Task
  ↓
Privileged Principal
  ↓
Action
```

A privileged principal becomes interesting only when the lower-privileged user can influence the action or its execution environment.

---

## 6. Inspect Task Actions

Determine what the task actually executes.

PowerShell:

```powershell
(Get-ScheduledTask -TaskName "<TaskName>").Actions
```

Look for:

```text
Execute
Arguments
WorkingDirectory
```

The action may execute:

* An executable.
* A PowerShell script.
* A batch file.
* Another script interpreter.
* A command with arguments.

Record the complete action.

---

## 7. Analyze the Executable Path

Example:

```text
Action:
C:\Program Files\Example\backup.exe
```

Investigate:

```text
Executable
    ↓
Parent Directory
    ↓
Parent Directories
    ↓
Required Files / DLLs
```

Check permissions:

```cmd
icacls "C:\Program Files\Example\backup.exe"
```

and:

```cmd
icacls "C:\Program Files\Example"
```

The key question is:

> **Can the current user modify something that the privileged task executes?**

---

## 8. Script-Based Tasks

Tasks may execute scripts such as:

```text
.ps1
.bat
.cmd
.vbs
.js
```

For a script-based task, investigate:

```text
Task
 ↓
Interpreter
 ↓
Script
 ↓
Script Directory
 ↓
Referenced Files
 ↓
Permissions
```

Example:

```text
powershell.exe
    ↓
C:\Scripts\backup.ps1
```

Check:

```cmd
icacls "C:\Scripts\backup.ps1"
```

and the containing directory.

A writable script can be security-relevant when the task executes it with a higher-privileged account.

---

## 9. Task Arguments

Arguments can significantly change the execution behavior.

Example:

```text
backup.exe -config C:\ProgramData\backup.conf
```

The executable itself may be protected while the configuration file is writable.

Therefore investigate:

```text
Executable
Arguments
Configuration Files
Input Files
Output Files
Working Directory
```

Each can potentially influence execution.

---

## 10. Working Directory

Where supported, inspect the task's working directory.

The working directory can matter because applications may resolve:

* Relative file paths.
* Configuration files.
* DLLs.
* Scripts.
* Other resources.

The investigation should establish whether a privileged task depends on a location controlled by a lower-privileged user.

---

## 11. Task Triggers

Identify how and when the task executes.

Common triggers include:

```text
At startup
At logon
On a schedule
On idle
On an event
On workstation unlock
On system state changes
```

PowerShell:

```powershell
(Get-ScheduledTask -TaskName "<TaskName>").Triggers
```

The trigger determines when a potential escalation path can be exercised.

---

## 12. Task Frequency

Record:

```text
Trigger:
Frequency:
Next Run:
Last Run:
```

This helps determine whether a task executes:

```text
Immediately
Periodically
At startup
Only after a particular event
Only under a particular user condition
```

Do not repeatedly trigger a task merely to test it unless the action is authorized and understood.

---

## 13. Task Settings

Inspect task settings where relevant:

```powershell
(Get-ScheduledTask -TaskName "<TaskName>").Settings
```

Potentially relevant settings include:

* Whether the task can run on demand.
* Whether multiple instances are allowed.
* Whether the task is enabled.
* Execution time limits.
* Conditions required for execution.

These settings help determine the practical behavior of the task.

---

## 14. Task File Locations

Task definitions are stored under the Windows Task Scheduler infrastructure.

A common location is:

```text
C:\Windows\System32\Tasks\
```

You can inspect the directory:

```cmd
dir C:\Windows\System32\Tasks
```

Do not modify task definition files during routine enumeration.

The task definition should be treated as a configuration artifact whose permissions and contents may be investigated where authorized.

---

## 15. Inspect Task XML

Windows Task Scheduler stores task definitions in XML form.

PowerShell can export or inspect task definitions through the Task Scheduler interfaces.

Example:

```powershell
Export-ScheduledTask -TaskName "<TaskName>"
```

The XML can reveal:

* Principal.
* Actions.
* Triggers.
* Settings.
* Conditions.
* Other task metadata.

This can be easier to analyze than a compact task listing.

---

## 16. Task Permissions

A task may have its own security descriptor controlling who can:

* Read it.
* Run it.
* Modify it.
* Delete it.
* Register or update it.

Where appropriate, inspect task security information using Windows-native task management tools or security descriptors.

The important question is:

> **Can the current user modify or control the task itself?**

This is separate from whether the user can modify the executable or script that the task runs.

---

## 17. Two Different Attack Surfaces

Separate task-related findings into two categories.

### Task Configuration

```text
Current User
      ↓
Can modify task?
      ↓
Change action/principal/configuration
```

### Task Resource

```text
Current User
      ↓
Cannot modify task
      ↓
Can modify executable/script/configuration?
      ↓
Privileged task executes modified resource
```

Both can produce a privilege boundary, but they require different validation.

---

## 18. Task Principal vs Task Resource

Use this comparison:

| Question                                 | Why it matters                      |
| ---------------------------------------- | ----------------------------------- |
| Who runs the task?                       | Determines security context         |
| What triggers it?                        | Determines execution opportunity    |
| What action does it perform?             | Determines what actually executes   |
| What arguments are used?                 | May influence execution             |
| Where is the executable?                 | Determines resource location        |
| Who can modify it?                       | Determines control                  |
| Can the task itself be modified?         | Determines configuration control    |
| Can it be triggered by the current user? | Determines practical exploitability |

---

## 19. Common Scheduled-Task Findings

Potential findings include:

* Privileged task executing a writable executable.
* Privileged task executing a writable script.
* Writable directory containing a task resource.
* Writable configuration/input file used by a privileged task.
* Weak permissions on the task itself.
* Task configured with an unnecessarily privileged principal.
* Unsafe execution path.
* Task relying on a user-controlled location.

Each finding requires validation.

---

## 20. Example Reasoning

Suppose enumeration reveals:

```text
Task:
DailyBackup

Principal:
SYSTEM

Action:
C:\Backup\backup.ps1
```

Do not immediately conclude that this is exploitable.

Investigate:

```text
SYSTEM task
    ↓
Executes backup.ps1
    ↓
Can current user modify backup.ps1?
        │
       No ──→ Investigate other dependencies
        │
       Yes
        ↓
Does the task actually execute the script?
        ↓
Can the task be triggered or will it execute naturally?
        ↓
Is testing authorized?
        ↓
Validate the privilege boundary
```

This is the workflow's preferred reasoning pattern.

---

## 21. Avoid Common False Positives

```text
SYSTEM task
    ≠
Vulnerable task

Writable file
    ≠
Privilege escalation

Script file
    ≠
Automatically exploitable

Task can run on demand
    ≠
Current user can necessarily run it

Privileged task
    ≠
Current user can control it
```

Always establish the complete chain.

---

## 22. Build a Task Map

For each interesting task:

```text
TASK MAP
--------

Task Name:
Task Path:

State:
Enabled:

Principal:
Run Level:
Logon Type:

Trigger:
Frequency:
Next Run:

Action:
Executable:
Arguments:
Working Directory:

Executable Permissions:
Directory Permissions:

Task Permissions:

Configuration/Input Files:

Potential Writable Resource:

Can Current User Trigger It?

Potential Privilege Boundary:

Validation Required:
```

---

## 23. Scheduled Task Decision Tree

```text
                  Scheduled Task
                        │
                        ▼
                 Who runs it?
                        │
                        ▼
               Privileged context?
                  /          \
                No            Yes
                │              │
                ▼              ▼
             Record       Inspect action
                               │
                               ▼
                         What does it run?
                               │
                    ┌──────────┼──────────┐
                    │          │          │
                    ▼          ▼          ▼
                   EXE       Script      Config
                    │          │          │
                    └──────────┼──────────┘
                               ▼
                    Can current user modify
                       or influence it?
                          /         \
                        No           Yes
                        │             │
                        ▼             ▼
                  Continue        Validate
                 enumeration       path
```

---

## 24. Scheduled Tasks Checklist

```text
[ ] Scheduled tasks enumerated
[ ] Task names recorded
[ ] Task states identified
[ ] Task principals identified
[ ] Privileged principals identified
[ ] Task actions identified
[ ] Executables/scripts identified
[ ] Arguments reviewed
[ ] Working directories reviewed
[ ] Triggers identified
[ ] Frequency reviewed
[ ] Task settings reviewed
[ ] Task definition locations identified
[ ] Task XML reviewed where useful
[ ] Task permissions considered
[ ] Executable permissions checked
[ ] Script permissions checked
[ ] Directory permissions checked
[ ] Configuration/input files investigated
[ ] Triggerability considered
[ ] Potential privilege boundaries documented
[ ] False positives eliminated
```

---

## 25. Decision Point

After scheduled-task enumeration:

```text
                 Scheduled Task
                       │
                       ▼
              Privileged execution?
                    /       \
                  No         Yes
                  │           │
                  ▼           ▼
               Record    Execution chain
                              │
               ┌──────────────┼──────────────┐
               │              │              │
               ▼              ▼              ▼
             Task           Action        Resources
            itself          executed       used
               │              │              │
               └──────────────┼──────────────┘
                              ▼
                    Current user influence?
                          /       \
                        No         Yes
                        │           │
                        ▼           ▼
                   Continue      Validate
                   workflow       finding
```

---

## Next Step

Proceed to:

```text
08-Filesystem-and-Permissions/
```

The next stage is critical because many of the leads discovered so far eventually depend on **NTFS permissions and ACLs**.

The central question becomes:

> **What can the current user actually read, write, modify, execute, or take ownership of — and does any of that intersect with a privileged execution path?**
