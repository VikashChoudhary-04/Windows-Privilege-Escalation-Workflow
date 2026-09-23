# Network Enumeration

Network enumeration identifies how the Windows host communicates with other systems and which services are exposed locally or remotely.

For privilege escalation, the objective is not simply to collect IP addresses and ports.

The goal is to understand:

```text
Network Interfaces
        ↓
Routes
        ↓
Listening Services
        ↓
Processes
        ↓
Service Accounts
        ↓
Firewall / Access Controls
        ↓
Shares and Remote Resources
        ↓
Potential Privilege Boundaries
```

Network information can reveal privileged services, administrative interfaces, exposed applications, trust relationships, and resources that become relevant when combined with findings from earlier stages.

---

## 1. Objective

Determine:

* Host IP addresses
* Network interfaces
* Default gateway
* Routing information
* DNS configuration
* Listening ports
* Established connections
* Processes associated with network services
* Services bound to network interfaces
* Windows Firewall context
* SMB shares
* Remote-management services
* Domain/network relationships
* Locally exposed applications
* Network paths that may affect privilege escalation

The key question is:

> **Does the network configuration expose a service, trust relationship, or privileged resource that can influence the current privilege boundary?**

---

## 2. Network Enumeration Mindset

Do not treat network enumeration as a separate activity from the rest of the workflow.

Connect network information to earlier findings.

For example:

```text
Listening Port
      ↓
Process
      ↓
Service
      ↓
Service Account
      ↓
Configuration
      ↓
Permissions
      ↓
Privilege Impact
```

Another useful relationship:

```text
Network Service
      ↓
Application
      ↓
Configuration
      ↓
Credential
      ↓
Privileged Account
```

The value comes from the relationships between findings.

---

## 3. Network Interfaces

Start with the host's interfaces.

```cmd
ipconfig
```

For detailed information:

```cmd
ipconfig /all
```

Record:

* Interface name
* IPv4 address
* IPv6 address
* Subnet mask
* Default gateway
* DNS servers
* DHCP status
* MAC address
* Interface state

PowerShell:

```powershell
Get-NetIPConfiguration
```

For interface details:

```powershell
Get-NetIPInterface
```

---

## 4. Interface Analysis

Identify which interfaces are active.

Typical interfaces may include:

```text
Ethernet
Wi-Fi
VPN
Virtual adapters
Loopback
Hyper-V adapters
VMware adapters
Docker adapters
```

An additional interface may reveal:

* Virtualized environments
* Lab networks
* Internal networks
* VPN connectivity
* Multiple security zones
* Management networks

Do not assume that an additional interface automatically provides a privilege-escalation path.

Determine what resources are accessible through it.

---

## 5. Routing Table

Review routing information:

```cmd
route print
```

PowerShell:

```powershell
Get-NetRoute
```

Look for:

* Default route
* Directly connected networks
* Internal networks
* VPN routes
* Static routes
* Multiple gateways
* Unexpected routes

Conceptually:

```text
Current Host
     |
     +---- Network A
     |
     +---- Network B
     |
     +---- VPN Network
```

This can reveal network relationships that explain how privileged services or administrative systems are accessed.

---

## 6. DNS Configuration

Review DNS configuration:

```cmd
ipconfig /all
```

PowerShell:

```powershell
Get-DnsClientServerAddress
```

Record:

* DNS servers
* DNS suffix
* Connection-specific DNS suffix
* Domain-related configuration

If the host is domain joined, DNS configuration can help explain its relationship with domain infrastructure.

---

## 7. Listening Ports

Identify listening network sockets:

```cmd
netstat -ano
```

PowerShell:

```powershell
Get-NetTCPConnection -State Listen
```

For UDP:

```powershell
Get-NetUDPEndpoint
```

Record:

```text
Local Address
Local Port
Remote Address
Remote Port
State
PID
```

The PID is especially important because it allows the network socket to be mapped back to a process.

---

## 8. Map Ports to Processes

Start with:

```cmd
netstat -ano
```

Then identify the corresponding process:

```cmd
tasklist /fi "PID eq <PID>"
```

PowerShell:

```powershell
Get-Process -Id <PID>
```

Build the relationship:

```text
Port
 ↓
PID
 ↓
Process
 ↓
Executable
 ↓
Account
 ↓
Service/Application
```

Example:

```text
Port 8080
   ↓
PID 1234
   ↓
custom-server.exe
   ↓
SYSTEM
   ↓
Windows Service
```

This is far more useful than simply recording that port `8080` is open.

---

## 9. Localhost-Only Services

Pay attention to services bound to:

```text
127.0.0.1
::1
```

A service that is not exposed externally may still be important because it can be accessed locally by the current user.

Examples include:

```text
Local administration interfaces
Development servers
Management APIs
Databases
Monitoring interfaces
Internal application endpoints
```

Ask:

```text
Who can access it?
        ↓
What does it provide?
        ↓
Which account runs it?
        ↓
Does it expose privileged functionality?
```

---

## 10. All-Interface Services

Services bound to:

```text
0.0.0.0
::
```

may listen on multiple interfaces.

Determine:

* Which process owns the port
* Which account runs it
* Whether authentication is required
* Which firewall rules apply
* Whether the service is intended to be remotely accessible

Do not treat `0.0.0.0` as a vulnerability by itself.

It is an exposure indicator that requires further analysis.

---

## 11. Established Connections

Review current connections:

```cmd
netstat -ano
```

PowerShell:

```powershell
Get-NetTCPConnection -State Established
```

Determine:

```text
Local process
Remote address
Remote port
Connection state
Process owner
```

This may reveal:

* Management connections
* Database connections
* Application backends
* Remote administration
* Monitoring infrastructure
* Domain-related services

Do not assume that every connection represents a security weakness.

Use it to understand the host's operational relationships.

---

## 12. Process-to-Network Mapping

Combine earlier process enumeration with network information.

```text
Process
   ↓
PID
   ↓
Listening Port
   ↓
Interface
   ↓
Service
   ↓
Account
```

PowerShell can help identify processes with network-related information:

```powershell
Get-NetTCPConnection |
Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
```

Then correlate `OwningProcess` with:

```powershell
Get-Process
```

This creates a useful service map.

---

## 13. Service-to-Network Mapping

For a network-facing service:

```cmd
sc qc <service>
```

PowerShell:

```powershell
Get-CimInstance Win32_Service |
Select-Object Name,StartName,State,PathName
```

Map:

```text
Network Port
      ↓
Process
      ↓
Service
      ↓
Service Account
      ↓
Binary
      ↓
Configuration
      ↓
Permissions
```

This is especially important when the service runs as:

```text
LocalSystem
Administrator
Custom privileged account
Domain account
```

---

## 14. Windows Firewall

Review firewall profiles:

```powershell
Get-NetFirewallProfile
```

List relevant firewall rules:

```powershell
Get-NetFirewallRule |
Select-Object DisplayName,Enabled,Direction,Action
```

Additional filtering may be needed when investigating a specific port or application.

Firewall analysis should answer:

```text
Is the service reachable?
        ↓
From where?
        ↓
On which interface?
        ↓
Under which firewall profile?
```

A listening service does not necessarily mean that it is remotely reachable.

---

## 15. Firewall and Service Relationship

Build this relationship:

```text
Service
   ↓
Listening Port
   ↓
Network Interface
   ↓
Firewall Rule
   ↓
Reachability
```

Example:

```text
Privileged Service
      ↓
TCP 8443
      ↓
0.0.0.0
      ↓
Firewall allows inbound traffic
      ↓
Remote access possible
```

This becomes a meaningful investigation lead.

---

## 16. SMB Enumeration

Windows commonly uses SMB for file and administrative sharing.

List local shares:

```cmd
net share
```

PowerShell:

```powershell
Get-SmbShare
```

For a specific share:

```powershell
Get-SmbShareAccess -Name <share>
```

Investigate:

* Share name
* Local path
* Share permissions
* NTFS permissions
* Accessible users/groups
* Administrative shares
* Sensitive files
* Writable locations

Remember:

> SMB share permissions and NTFS permissions are separate layers.

Effective access depends on both.

---

## 17. Administrative Shares

Common administrative shares include:

```text
C$
ADMIN$
IPC$
```

Their presence on a Windows system is normal and does not automatically represent a vulnerability.

The important questions are:

```text
Who can access the share?
        ↓
What authentication is required?
        ↓
What local path does it expose?
        ↓
What permissions apply?
```

Do not classify standard administrative shares as findings without additional evidence.

---

## 18. Network Shares and Privilege Escalation

A network share becomes more interesting when it provides access to:

```text
Configuration files
Credential material
Backup files
Deployment files
Scripts
Application data
Administrative resources
```

Reasoning model:

```text
Accessible Share
      ↓
Sensitive Resource
      ↓
Credential / Configuration
      ↓
Privileged Account
      ↓
Privilege Boundary
```

A writable share can also be relevant if a privileged process consumes files from that location.

---

## 19. Remote Management Services

Identify whether remote-management services are present.

Common Windows technologies include:

```text
RDP
WinRM
SMB
RPC
PowerShell Remoting
WMI/DCOM
```

Identify relevant services and ports.

Examples:

```text
RDP     → TCP 3389
WinRM   → TCP 5985 / 5986
SMB     → TCP 445
```

The presence of these services is not inherently a privilege-escalation vulnerability.

Determine:

* Who can authenticate
* Which groups are allowed
* What account context is obtained
* Whether credentials discovered earlier provide access
* Whether the service exposes an administrative boundary

---

## 20. Domain Network Context

If the system is domain joined, identify the domain context:

```cmd
whoami
```

```cmd
systeminfo
```

```cmd
echo %USERDOMAIN%
```

```cmd
echo %LOGONSERVER%
```

PowerShell:

```powershell
$env:USERDOMAIN
$env:LOGONSERVER
```

The purpose is to understand:

```text
Local Identity
      ↓
Domain Identity
      ↓
Domain Infrastructure
      ↓
Network Services
      ↓
Available Trust Relationships
```

Do not assume domain membership automatically provides an escalation path.

---

## 21. Network Configuration Files

Application and service configurations may contain network information such as:

```text
Database hosts
Internal API endpoints
Management servers
Proxy settings
Monitoring servers
Authentication endpoints
```

Review relevant application configuration identified in earlier stages.

Connect:

```text
Application
    ↓
Configuration
    ↓
Network Endpoint
    ↓
Authentication
    ↓
Account / Privilege
```

This is often more useful than generic port scanning.

---

## 22. Network Interfaces and Virtualization

Virtual interfaces may reveal:

```text
Hyper-V
VMware
VirtualBox
Docker
VPN
Container networks
```

Useful commands:

```cmd
ipconfig /all
```

```cmd
route print
```

The presence of virtual networks can explain otherwise unexpected interfaces or routes.

Do not treat virtualization interfaces as vulnerabilities without additional evidence.

---

## 23. Local Network Services

Look for services that expose management or application functionality locally.

Examples:

```text
HTTP/HTTPS
Databases
Development servers
Monitoring interfaces
Custom APIs
RPC services
Management consoles
```

For each service ask:

```text
Who owns the process?
        ↓
Which account runs it?
        ↓
What functionality is exposed?
        ↓
Can the current user interact with it?
        ↓
Can that interaction affect privileged execution?
```

---

## 24. Network-Based Credential Relationships

Network enumeration should connect with the credential stage.

Example:

```text
Configuration file
      ↓
Database credentials
      ↓
Database service
      ↓
Database account
      ↓
Application access
```

Or:

```text
Credential discovered
      ↓
WinRM / RDP / SMB access
      ↓
Higher-privileged account
      ↓
Authorized validation
```

The credential itself is not the final finding.

Its permissions and resulting access determine the security impact.

---

## 25. Network Finding Classification

### Observation

A network service exists.

```text
TCP 8080
```

### Lead

The service is privileged or exposes an interesting application.

```text
TCP 8080
    ↓
Process runs as SYSTEM
    ↓
Custom management interface
```

### Validated Finding

Authorized testing confirms that the exposed functionality allows the current user to cross a privilege boundary.

```text
Network Service
      ↓
Privileged Functionality
      ↓
Current User Access
      ↓
Authorized Validation
      ↓
Privilege Boundary Crossed
```

Keep these categories separate.

---

## 26. Common False Positives

Avoid automatically treating the following as vulnerabilities:

* Open ports
* Listening on `0.0.0.0`
* Localhost-only services
* RDP being enabled
* SMB being enabled
* Administrative shares
* Domain membership
* Virtual network adapters
* Established outbound connections
* Firewall rules that appear permissive without confirming reachability
* Services that require appropriate authentication

Network exposure becomes significant when it connects to an actual security boundary.

---

## 27. Network Investigation Workflow

Use this sequence:

```text
Identify Interfaces
        ↓
Review Routes
        ↓
Review DNS
        ↓
Enumerate Listening Ports
        ↓
Map Ports to Processes
        ↓
Map Processes to Services
        ↓
Identify Service Accounts
        ↓
Review Firewall Context
        ↓
Review Shares
        ↓
Review Remote Management
        ↓
Connect with Credentials / Applications
        ↓
Validate Relevant Findings
```

---

## 28. Network Map

Maintain a simple map:

```text
Host
 |
 +-- Interface
 |      |
 |      +-- IP
 |      +-- Gateway
 |      +-- DNS
 |
 +-- Listening Service
 |      |
 |      +-- Port
 |      +-- Process
 |      +-- Account
 |
 +-- SMB Shares
 |
 +-- Remote Management
 |
 +-- Firewall Rules
 |
 +-- External Connections
```

This makes relationships easier to reason about.

---

## 29. Network Enumeration Checklist

### Interfaces

* [ ] Interfaces enumerated
* [ ] IPv4 addresses recorded
* [ ] IPv6 addresses considered
* [ ] Gateway identified
* [ ] DNS configuration reviewed
* [ ] Virtual/VPN interfaces identified

### Routing

* [ ] Routing table reviewed
* [ ] Default route identified
* [ ] Internal networks identified
* [ ] VPN routes identified

### Ports and Services

* [ ] Listening TCP ports identified
* [ ] Listening UDP endpoints identified
* [ ] PIDs mapped
* [ ] Processes identified
* [ ] Services identified
* [ ] Service accounts identified

### Firewall

* [ ] Firewall profiles reviewed
* [ ] Relevant inbound rules reviewed
* [ ] Relevant outbound context considered
* [ ] Actual reachability considered

### Shares

* [ ] SMB shares enumerated
* [ ] Share permissions reviewed
* [ ] NTFS permissions considered
* [ ] Sensitive resources identified
* [ ] Administrative shares understood

### Remote Management

* [ ] RDP context reviewed
* [ ] WinRM context reviewed
* [ ] SMB/RPC context reviewed
* [ ] WMI/DCOM context considered

### Analysis

* [ ] Network services mapped to processes
* [ ] Processes mapped to accounts
* [ ] Privileged services identified
* [ ] Network relationships connected to previous findings
* [ ] False positives eliminated
* [ ] Relevant findings validated safely

---

## 30. What This Stage Should Produce

By the end of this stage, you should have:

```text
Network Configuration
        ↓
Interface and Route Map
        ↓
Listening Service Inventory
        ↓
Process / Service Mapping
        ↓
Firewall and Share Context
        ↓
Remote Management Context
        ↓
Network-Based Privilege-Escalation Candidates
```

The objective is not to produce the largest possible port list.

The objective is to understand **which network services exist, who controls them, how they are exposed, and whether they create a meaningful privilege boundary**.

---

## Next Step

Continue to:

```text
13-Windows-Misconfigurations/
```

The next stage will consolidate Windows-specific misconfiguration patterns and turn the findings from the previous enumeration stages into concrete privilege-escalation candidates.
