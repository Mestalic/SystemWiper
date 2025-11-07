# DeepAccess PowerShell Module

## Overview

The DeepAccess module is a comprehensive PowerShell framework for advanced Windows 11 system access beyond standard administrative rights. It provides legitimate, security-conscious access to protected system resources using official Windows APIs and best practices.

## ⚠️ Security Notice

This module is designed for **defensive security research, system administration, and legitimate security operations only**. All techniques align with Windows 11 security architecture and official Microsoft APIs. The module includes comprehensive logging and requires appropriate privileges.

**Use Cases:**
- Security research and testing
- System administration and diagnostics
- Incident response and forensics
- Compliance auditing
- Educational purposes in controlled environments

## Features

### 1. NTFS Change Journal (USN) Operations
- Initialize and modify USN journals
- Query journal status and metadata
- Delete and manage journal lifecycles
- Support for all journal operations per Microsoft documentation

### 2. Shadow Copy Management
- Create new shadow copies
- Enumerate existing shadow copies
- Get file paths within shadow copies
- Support for Volume Shadow Copy Service (VSS)

### 3. Registry Hive Handling
- Enumerate all registry hives and their file locations
- Test hive file accessibility (locked/unlocked status)
- Mount registry hives from files
- Dismount loaded hives
- Offline hive analysis support

### 4. System Service Operations
- List all system services with protection levels
- Get service protection status
- Identify PPL (Protected Process Light) services
- Service configuration analysis

### 5. Privilege Management
- Get current process privileges
- Test specific privilege availability
- Enable privileges for operations
- Support for all major system privileges:
  - SeBackupPrivilege
  - SeRestorePrivilege
  - SeDebugPrivilege
  - SeManageVolumePrivilege
  - And more...

### 6. LSASS and Security Protection
- Check LSA Protection status
- Verify Credential Guard configuration
- Test Secure Boot status
- Test HVCI (Hypervisor-Protected Code Integrity)
- Analyze protected process access

### 7. Protected Process Access
- Test access to protected processes (like LSASS)
- Identify PPL protected services
- Analyze process protection levels
- Safe process interaction testing

### 8. System Diagnostics
- Comprehensive system access summary
- Complete privilege audit
- Security protection status
- Service protection analysis
- Registry hive inventory

## Requirements

- **Operating System**: Windows 11 (Build 22H2+ recommended)
- **PowerShell**: 5.0 or later
- **Privileges**: Administrator rights required
- **Architecture**: x64

## Installation

1. Place `DeepAccess.ps1` in your desired directory
2. Open PowerShell as Administrator
3. Import the module:

```powershell
Import-Module .\DeepAccess.ps1
```

## Usage Examples

### Basic System Analysis

```powershell
# Get comprehensive system access summary
$summ = Get-SystemAccessSummary

# Check LSASS protection
$lsass = Get-LSASSProtectionStatus
$lsass.LSAProtection
$lsass.CredentialGuard

# Get current privileges
$privs = Get-CurrentPrivileges
$privs.Privileges | Where-Object { $_ -like "Se*" }
```

### USN Journal Operations

```powershell
# Initialize USN journal on C: drive
$journalId = Initialize-USNJournal -VolumePath "C:\" -MaximumSize 1073741824

# Query journal status
$status = Get-USNJournalStatus -VolumePath "C:\"
$status.UsnJournalID
$status.MaximumSize

# Delete journal
Remove-USNJournal -VolumePath "C:\"
```

### Shadow Copy Management

```powershell
# Get all shadow copies
$copies = Get-ShadowCopies

# Create new shadow copy
$copy = New-ShadowCopy -Volume "C:" -Description "Maintenance snapshot"

# Get file path in shadow copy
$shadowPath = Get-ShadowCopyPath -ShadowCopyId $copy.ShadowCopyId -FilePath "C:\Windows\System32\config\SAM"
```

### Registry Operations

```powershell
# Get all registry hives
$hives = Get-RegistryHiveInfo
$hives["HKLM\SAM"]

# Test hive accessibility
$accessible = Test-RegistryHiveAccessibility -HivePath "C:\Windows\System32\config\SAM"

# Mount hive
Mount-RegistryHive -HivePath "C:\Users\backup\ntuser.dat" -HiveName "TempUserHive"

# Work with hive...
Dismount-RegistryHive -HiveName "TempUserHive"
```

### Privilege Testing

```powershell
# Test specific privilege
$backupPriv = Test-Privilege "SeBackupPrivilege"
$backupPriv.HasPrivilege

# Get secure file access
$fileAccess = Get-SecureFileAccess -FilePath "C:\Windows\System32\config\SAM" -ReadOnly
$fileAccess.AccessGranted
```

### Service Protection

```powershell
# Get all services with protection info
$services = Get-SystemServices
$services | Where-Object { $_.ProtectionLevel -ne "Standard" }

# Check specific service protection
$svc = Get-ServiceProtectionStatus -ServiceName "WinDefend"
$svc.IsProtected
$svc.ProtectionLevel
```

### Protected Process Testing

```powershell
# Test access to LSASS
$lsass = Get-Process -Name "lsass" -ErrorAction SilentlyContinue
if ($lsass) {
    $access = Test-ProtectedProcessAccess -ProcessId $lsass.Id
    $access.IsProtected
    $access.CanReadMemory
}
```

## Function Reference

### Core Functions

| Function | Description | Required Privilege |
|----------|-------------|-------------------|
| `Get-SystemAccessSummary` | Comprehensive system access analysis | Administrator |
| `Get-CurrentPrivileges` | Get all current process privileges | Administrator |
| `Test-Privilege` | Test specific privilege availability | None |
| `Get-LSASSProtectionStatus` | Check LSASS protection status | None |

### USN Journal Functions

| Function | Description | Required Privilege |
|----------|-------------|-------------------|
| `Initialize-USNJournal` | Create/modify USN journal | Administrator |
| `Get-USNJournalStatus` | Query journal status | Administrator |
| `Remove-USNJournal` | Delete USN journal | Administrator |

### Shadow Copy Functions

| Function | Description | Required Privilege |
|----------|-------------|-------------------|
| `Get-ShadowCopies` | List all shadow copies | Administrator |
| `New-ShadowCopy` | Create new shadow copy | Administrator |
| `Get-ShadowCopyPath` | Get file path in shadow copy | Administrator |

### Registry Functions

| Function | Description | Required Privilege |
|----------|-------------|-------------------|
| `Get-RegistryHiveInfo` | Get hive file locations | Administrator |
| `Test-RegistryHiveAccessibility` | Test if hive is locked | None |
| `Mount-RegistryHive` | Load hive from file | Administrator |
| `Dismount-RegistryHive` | Unload loaded hive | Administrator |

### Service Functions

| Function | Description | Required Privilege |
|----------|-------------|-------------------|
| `Get-SystemServices` | List services with protection info | Administrator |
| `Get-ServiceProtectionStatus` | Check service protection | Administrator |

### Process Functions

| Function | Description | Required Privilege |
|----------|-------------|-------------------|
| `Test-ProtectedProcessAccess` | Test protected process access | SeDebugPrivilege |
| `Get-SecureFileAccess` | Access protected files | SeBackupPrivilege |

## Security Considerations

### Privilege Requirements

All operations require Administrator privileges. Some functions additionally require:
- `SeBackupPrivilege`: For reading protected file content
- `SeRestorePrivilege`: For writing/restoring system files
- `SeDebugPrivilege`: For debugging protected processes
- `SeManageVolumePrivilege`: For volume-level operations

### Protection Mechanisms

The module is designed to work WITH Windows 11's protection mechanisms:

- **LSA Protection**: Cannot bypass; module reports protection status
- **Credential Guard**: Respects isolation; no direct LSASS access
- **PPL Services**: Cannot terminate or debug protected services
- **Code Integrity**: Respects signing requirements
- **UAC**: Functions as designed with elevation prompts

### Logging and Auditing

All operations are logged with:
- Timestamp
- Operation type
- User context
- Success/failure status

The module includes `Write-DeepAccessLog` for comprehensive audit trail.

## Architecture

The module is structured into several functional areas:

```
DeepAccess.ps1
├── Core Utilities
│   ├── Logging system
│   ├── Privilege management
│   └── Process utilities
├── USN Journal Operations
│   ├── Initialize, Query, Delete
│   └── Journal status management
├── Shadow Copy Management
│   ├── Enumerate, Create
│   └── Path resolution
├── Registry Operations
│   ├── Hive enumeration
│   ├── Accessibility testing
│   └── Mount/unload support
├── Service Management
│   ├── Service listing
│   └── Protection analysis
├── Security Protection
│   ├── LSASS status
│   ├── Credential Guard
│   └── Protected process testing
└── Diagnostics
    ├── System summary
    ├── Privilege audit
    └── Security analysis
```

## Compatibility

### Windows 11 Features
- Full support for Windows 11 security architecture
- Compatible with latest protection mechanisms
- Respects modern security boundaries

### Legacy Compatibility
- Works on Windows Server 2022
- Compatible with Windows 10 (with limitations)
- Some features may not be available on older systems

## Examples and Use Cases

### 1. Security Assessment
```powershell
# Comprehensive security assessment
$summ = Get-SystemAccessSummary
$summ.LSASSProtection.LSAProtection  # Should be True
$summ.LSASSProtection.CredentialGuard  # Should be True
```

### 2. System Maintenance
```powershell
# Create maintenance snapshot
$copy = New-ShadowCopy -Volume "C:" -Description "Pre-maintenance backup"
```

### 3. Forensic Analysis
```powershell
# Access shadow copy for file recovery
$copies = Get-ShadowCopies
$path = Get-ShadowCopyPath -ShadowCopyId $copies[0].ShadowCopyId -FilePath "C:\DeletedFile.txt"
```

### 4. Service Analysis
```powershell
# Find protected services
$protected = Get-SystemServices | Where-Object { $_.ProtectionLevel -ne "Standard" }
```

## Best Practices

1. **Always run as Administrator**: Most functions require elevated privileges
2. **Test in isolated environments**: Use VMs or test systems
3. **Document all operations**: Use the built-in logging
4. **Respect security boundaries**: Don't attempt to bypass protections
5. **Backup before modifications**: Use shadow copies or other backup methods
6. **Follow least privilege**: Only enable required privileges

## Troubleshooting

### Common Issues

**"Access Denied" errors:**
- Ensure running as Administrator
- Check if privilege is enabled
- Verify UAC settings

**"Function not found" errors:**
- Import module: `Import-Module .\DeepAccess.ps1`
- Check PowerShell execution policy

**Shadow copy operations failing:**
- Verify VSS service is running
- Check disk space for shadow copies
- Ensure appropriate privileges

**Registry hive locked:**
- Hives are locked when in use by running system
- Use offline tools or WinPE for locked hives
- Mount failed hives can be accessed in offline mode

## Contributing

This module is designed for security research and legitimate system administration. When contributing:
- Follow security best practices
- Include comprehensive error handling
- Add detailed documentation
- Test on latest Windows 11 builds
- Respect existing security boundaries

## License and Disclaimer

This module is provided for educational and legitimate security research purposes. Users are responsible for:
- Compliance with all applicable laws
- Adherence to organizational security policies
- Proper testing in controlled environments
- Appropriate use of obtained information

The authors are not responsible for any misuse of this software.

## Version History

- **v1.0.0** - Initial release
  - Complete USN journal support
  - Shadow copy management
  - Registry hive handling
  - Service protection analysis
  - LSASS protection checking
  - Comprehensive system diagnostics

## References

- Windows 11 Security Architecture Documentation
- Microsoft Learn: NTFS Change Journal
- Microsoft Learn: Volume Shadow Copy Service
- Microsoft Learn: LSA Protection and Credential Guard
- Microsoft Learn: Protected Process Light (PPL)
- Windows Driver Development Kit (DDK)
- Windows Internals Documentation
