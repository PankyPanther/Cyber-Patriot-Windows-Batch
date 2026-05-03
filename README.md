# Little Bobby Tables — Windows Security Hardening Script

A Windows batch script designed to automate common system hardening tasks for security competitions and system administration. Must be run with Administrator privileges.

---

## Requirements

- Windows OS (tested on Windows 10/11 and Windows Server)
- Administrator privileges
- PowerShell (for password policy and Windows Update features)

---

## Usage

Right-click the `.bat` file and select **Run as administrator**, or launch it from an elevated Command Prompt.

```
right-click → Run as administrator
```

---

## Menu Options

### 1. Enable Firewall
Enables Windows Defender Firewall across all network profiles (Domain, Private, and Public) using `netsh advfirewall`.

### 2. Correct Policy Settings
Applies a series of security policies in sequence:

**Password Policies**
- Enforces password history (last 6 passwords)
- Maximum password age: 90 days
- Minimum password age: 30 days
- Minimum password length: 11 characters
- Enables password complexity requirements
- Disables reversible encryption for password storage

**Account Lockout Policies**
- Lockout threshold: 10 failed attempts
- Lockout duration: 30 minutes
- Lockout counter reset: 30 minutes

**Security Policies**
- Restricts blank password use to console logins only
- Disables anonymous enumeration of SAM accounts
- Forces a Group Policy update (`gpupdate /force`)

### 3. Services
Stops and disables the Microsoft FTP Service (`ftpsvc`).

### 4. Disable Remote Connections
Disables the following remote access features via registry:
- Remote Desktop (RDP)
- Auto Admin Logon
- Remote Assistance

### 5. Create Group
Interactively creates a new local user group and allows you to add users to it one at a time.

### 6. User Management
Reads a structured text file of authorized users and performs the following:
- Parses `Authorized Administrators` and `Authorized Users` sections
- Reads a `Roles` section to detect privilege mismatches
  - Prompts to **grant** admin rights to users missing them
  - Prompts to **revoke** admin rights from users who shouldn't have them
- Detects users on the machine not present in the authorized list and prompts for deletion
- Prompts to reset passwords for authorized users (sets a predefined secure password)

#### User file format
```
Authorized Administrators
alice
bob

Authorized Users
charlie
dave

Roles
alice: admin
bob: user
charlie: user
dave: admin
```

### 7. Windows Update
Installs the `PSWindowsUpdate` PowerShell module if not present, lists available updates, and prompts before installing them.

---

## Special Options

| Option | Action |
|--------|--------|
| `-1`   | Exit the script |
| `69`   | Reboot the system (`shutdown /r`) |

---

## Notes

- The **User Management** module sets all authorized user passwords to a hardcoded value (`LittleBobby@123!`). It is strongly recommended to change this before deploying in any real environment.
- The script skips password changes for the currently logged-in user to avoid self-lockout.
- All registry changes are applied with `/f` to force without confirmation prompts.

---

## Author

Written by **Sage Tipton**
