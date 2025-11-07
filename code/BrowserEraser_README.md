# BrowserEraser.ps1 - Usage Guide

## Overview

BrowserEraser.ps1 is a comprehensive PowerShell script designed to securely remove browser credential data across all major browsers on Windows 11 systems. It implements DPAPI decryption for Chromium-based browsers and secure deletion of credential databases.

## Supported Browsers

### Chromium-Based Browsers
- **Microsoft Edge** (Chromium-based)
- **Google Chrome**
- **Opera** (including Opera Stable, Opera Developer)
- **Vivaldi**
- **Brave**

### Firefox-Based Browsers
- **Mozilla Firefox**
- **Tor Browser**

## Targeted Files and Data

### Chromium Browsers
- **Login Data** (SQLite) - Saved passwords
- **Cookies** (SQLite) - Browser cookies
- **Web Data** (SQLite) - Autofill and form history
- **Local Storage** (LevelDB) - Site data
- **Session Storage** (LevelDB) - Session data
- **Local State** (JSON) - DPAPI-encrypted AES keys
- All user profiles (Default, Profile 1, etc.)

### Firefox
- **logins.json** - Saved login credentials
- **key4.db** (and legacy key3.db) - Decryption keys
- **cookies.sqlite** - Browser cookies
- **formhistory.sqlite** - Form autocomplete data
- **places.sqlite** - History and bookmarks
- **sessionstore.jsonlz4** - Session restoration data
- **sessionstore-backups/** - Session backup files
- **cert9.db** - Security certificates

### Tor Browser
- Same files as Firefox in TorBrowser/Data/Browser/Profiles/

## Key Features

### 1. DPAPI Decryption
- Automatically detects and processes DPAPI-encrypted AES keys in Local State files
- Handles the complete Chromium credential encryption workflow
- Logs successful key detection and removal

### 2. Profile Detection
- Automatically discovers all user profiles via Windows registry
- Searches both LocalAppData and AppData paths
- Detects multiple browser profiles per user

### 3. Secure Deletion
- Implements 3-pass overwriting before deletion
- First pass: Random data
- Second pass: Random data
- Third pass: Zeros
- Final step: File deletion

### 4. Comprehensive Logging
- Timestamped log entries
- Detailed operation tracking
- Error reporting and summary statistics
- Log file rotation with timestamps

## Usage Examples

### Basic Usage
```powershell
.\BrowserEraser.ps1
```
Runs with interactive prompt and secure deletion enabled.

### Dry Run Mode
```powershell
.\BrowserEraser.ps1 -DryRun
```
Shows what would be deleted without actually removing files. Safe for testing.

### No Deletion Mode
```powershell
.\BrowserEraser.ps1 -NoDelete
```
Comprehensive analysis without any deletion. Useful for auditing.

### Custom Log File
```powershell
.\BrowserEraser.ps1 -LogFile "MyCleanup_20251107.log"
```
Specifies a custom log file name.

### Force Mode
```powershell
.\BrowserEraser.ps1 -Force
```
Continues even if not running as administrator.

### Include System Profiles
```powershell
.\BrowserEraser.ps1 -IncludeSystemProfiles
```
Also processes system-level browser profiles (use with caution).

### Combined Options
```powershell
.\BrowserEraser.ps1 -DryRun -LogFile "audit_$(Get-Date -Format 'yyyyMMdd').log"
```
Safe testing with custom logging.

## Command Line Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-DryRun` | Switch | Preview mode - no actual deletion | False |
| `-NoDelete` | Switch | Analysis only - no deletion | False |
| `-LogFile` | String | Custom log file name | Auto-generated |
| `-Force` | Switch | Continue without admin rights | False |
| `-IncludeSystemProfiles` | Switch | Process system profiles | False |

## Output

### Console Output
All operations are logged to console with timestamps:
```
[2025-11-07 17:11:56] [INFO] ========================================
[2025-11-07 17:11:56] [INFO] BrowserEraser v1.0 - Starting Cleanup
[2025-11-07 17:11:56] [INFO] ========================================
[2025-11-07 17:11:56] [INFO] Log file: BrowserEraser_20251107_171156.log
[2025-11-07 17:11:56] [INFO] DELETION MODE - Files will be securely deleted
[2025-11-07 17:11:56] [INFO] ========================================
[2025-11-07 17:11:56] [INFO] Detecting User Profiles
[2025-11-07 17:11:56] [INFO] Found 1 user profiles
```

### Log File
Detailed operations are saved to a timestamped log file with:
- Timestamp of each operation
- Log level (INFO, WARNING, ERROR, SUCCESS)
- Detailed file operations
- Summary statistics
- Error tracking

### Summary Report
At completion, the script provides:
- Total files deleted
- Total bytes securely overwritten
- Total size in MB
- List of any errors encountered

## Security Considerations

### Administrator Privileges
- Recommended for secure deletion of system-protected files
- The script checks for admin rights and warns if not present
- Use `-Force` to continue without admin privileges (limited functionality)

### DPAPI Protection
- Chromium browsers use Windows DPAPI for credential encryption
- AES keys are stored in Local State files, protected by DPAPI
- The script automatically handles DPAPI decryption within the user context

### Secure Deletion
- Implements DoD 5220.22-M standard 3-pass overwriting
- First two passes: Random data
- Final pass: Zeros
- Files are only deleted after successful overwriting

## File Locations

### Per-User Data Paths
- **Chromium Browsers**: `%LOCALAPPDATA%\[Browser]\User Data\`
- **Firefox**: `%APPDATA%\Mozilla\Firefox\Profiles\`
- **Opera**: `%APPDATA%\Opera\[Profile]\`

### Specific Paths
- **Edge**: `%LOCALAPPDATA%\Microsoft\Edge\User Data\`
- **Chrome**: `%LOCALAPPDATA%\Google\Chrome\User Data\`
- **Brave**: `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\`
- **Vivaldi**: `%LOCALAPPDATA%\Vivaldi\User Data\`
- **Firefox**: `%APPDATA%\Mozilla\Firefox\Profiles\[profile]\`

## Error Handling

The script includes comprehensive error handling:
- Graceful handling of missing files/directories
- Registry access failures (continues with available data)
- Permission issues (logged but doesn't stop execution)
- DPAPI decryption failures (logs but continues)

## Limitations

1. **User Context**: DPAPI decryption works only in the original user context
2. **File Locks**: Files in use may not be deletable (browser must be closed)
3. **System Profiles**: System-level profiles require admin rights
4. **Encryption**: Cannot decrypt Firefox master passwords (removes key files instead)

## Compatibility

- **Operating System**: Windows 11 (primary), Windows 10 (compatible)
- **PowerShell**: PowerShell 5.1 or later
- **.NET Framework**: 4.7.2 or later
- **Browsers**: All versions that use the documented storage formats

## Troubleshooting

### Common Issues

1. **"Access Denied" errors**
   - Ensure browser is closed
   - Run PowerShell as Administrator
   - Check for file locks

2. **"DPAPI decryption failed"**
   - Normal if running as different user
   - Key files will still be removed
   - Check log for specific details

3. **"No profiles found"**
   - Check registry permissions
   - Verify user profile paths exist
   - Run as administrator

### Performance

- Large profiles may take several minutes
- SSD drives enable faster secure deletion
- Consider using `-DryRun` first for timing estimates

## Legal and Ethical Use

This tool is intended for:
- Security research and testing
- Authorized penetration testing
- System cleanup and maintenance
- Compliance and auditing

**Use responsibly and only on systems you own or have explicit permission to test.**

## Version History

**v1.0** (2025-11-07)
- Initial release
- Support for all major browsers
- DPAPI decryption implementation
- Secure deletion with multiple overwrites
- Comprehensive logging and error handling

## Support

For issues or questions:
1. Check the log file for detailed error messages
2. Review the -DryRun output to verify file paths
3. Ensure all prerequisites are met
4. Test with -NoDelete first for analysis mode
