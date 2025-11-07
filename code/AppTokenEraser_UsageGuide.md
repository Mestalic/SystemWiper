# AppTokenEraser - Usage Guide

## Overview
`AppTokenEraser.ps1` is a comprehensive PowerShell tool designed to identify, extract, and securely delete application tokens and credentials from various software applications. The tool targets commonly used applications and services including gaming platforms, communication apps, creative software, and developer tools.

## Features

### Targeted Applications
- **Gaming**: Steam, Epic Games (EOS), Battle.net, Origin (EA App), Ubisoft Connect
- **Communication**: Discord
- **Streaming**: Spotify
- **Creative**: Adobe Creative Cloud
- **Productivity**: Office 365, Microsoft Store apps
- **Development**: GitHub, GitLab, Visual Studio Code
- **Browsers**: Chrome, Edge, Firefox (optional)

### Token Types Detected
- OAuth tokens (access_token, refresh_token)
- Session tokens and authentication cookies
- JSON Web Tokens (JWT)
- Personal Access Tokens (PATs)
- Base64 and hexadecimal encoded tokens
- API keys and authentication credentials

### Security Features
- NIST 800-88 aligned secure deletion
- Multi-pass overwriting (configurable)
- Registry value cleanup
- LevelDB database scanning
- Comprehensive logging and reporting

## Installation Requirements

### Prerequisites
- Windows PowerShell 5.1 or later
- Administrator privileges
- .NET Framework 4.7.2 or later

### Permissions
- The script requires Administrator rights to access certain registry keys and system directories
- Ensure you have appropriate permissions before running

## Usage

### Basic Usage
```powershell
# Run in dry-run mode (no actual deletions)
.\AppTokenEraser.ps1 -DryRun

# Run normally (will delete found tokens)
.\AppTokenEraser.ps1

# Enable verbose output
.\AppTokenEraser.ps1 -Verbose

# Include browser data in scan
.\AppTokenEraser.ps1 -IncludeBrowserData
```

### Advanced Options
```powershell
# Enable secure wiping with 3 passes
.\AppTokenEraser.ps1 -SecureWipe -WipePasses 3

# Run in dry-run mode with verbose logging
.\AppTokenEraser.ps1 -DryRun -Verbose

# Full scan including browser data with secure wiping
.\AppTokenEraser.ps1 -IncludeBrowserData -SecureWipe -Verbose
```

### Parameter Reference

| Parameter | Type | Description |
|-----------|------|-------------|
| `-DryRun` | Switch | Simulates actions without making changes |
| `-Verbose` | Switch | Provides detailed logging output |
| `-IncludeBrowserData` | Switch | Scans browser storage (Chrome, Edge, Firefox) |
| `-SecureWipe` | Switch | Enables NIST 800-88 compliant secure deletion |
| `-WipePasses` | Int | Number of overwrite passes (default: 1) |

## How It Works

### 1. Token Discovery
The script uses pattern matching to identify various token formats:
- OAuth tokens: `access_token=`, `refresh_token=`
- JWT: Base64 encoded with three parts separated by dots
- PATs: GitHub, GitLab, and other service-specific patterns
- Session tokens: Various authentication session formats

### 2. File System Scanning
- Searches application data directories
- Examines configuration files (.json, .xml, .ini, .vdf)
- Analyzes LevelDB databases (used by Discord, etc.)
- Processes registry keys for stored credentials

### 3. Credential Manager Integration
- Lists and removes Windows Credential Manager entries
- Targets platform-specific credentials (Office, Git, etc.)
- Provides comprehensive credential cleanup

### 4. Secure Deletion
When `-SecureWipe` is enabled:
- Uses cryptographically secure random data overwriting
- Implements NIST SP 800-88 guidelines
- Provides verification of deletion success
- Supports configurable overwrite passes

## Output and Logging

### Log File
- Location: `%TEMP%\AppTokenEraser_YYYYMMDD_HHMMSS.log`
- Contains detailed execution information
- Records all found tokens, deletions, and errors
- Provides final summary report

### Console Output
- Real-time progress updates
- Color-coded severity levels (Info, Warning, Error, Success)
- Token discovery notifications
- Deletion confirmation messages

## Safety Considerations

### Dry Run Mode
Always test with `-DryRun` first to:
- See what would be affected
- Verify the script's target identification
- Review the log file for accuracy
- Ensure appropriate permissions

### Backup Recommendations
- Create system restore point before running
- Export important configurations
- Document current state for comparison
- Test on non-production systems first

### Application Impact
- Some applications may require re-authentication
- Configuration files may be removed
- Browser sessions may be affected (with `-IncludeBrowserData`)
- Application settings might need reconfiguration

## Troubleshooting

### Common Issues

#### Access Denied Errors
- Ensure running as Administrator
- Check file/folder permissions
- Temporarily disable antivirus real-time protection
- Close applications that might be locking files

#### No Tokens Found
- This is normal if applications don't store tokens locally
- Tokens may be in memory only
- Use `-Verbose` to see all file processing
- Check if applications are actually installed

#### Secure Wipe Failures
- File may be in use by running applications
- Insufficient permissions
- Disk space issues
- Try with lower `-WipePasses` values

### Log Analysis
Review the generated log file for:
- Failed access attempts
- Token pattern matches
- Deletion success/failure status
- Registry access issues

## Best Practices

### Before Running
1. **Backup**: Create system restore point
2. **Documentation**: Note current application states
3. **Testing**: Use `-DryRun` mode first
4. **Permissions**: Verify Administrator access

### During Execution
1. **Monitor**: Watch console output for errors
2. **Applications**: Close unnecessary running apps
3. **Patience**: Allow adequate time for completion
4. **Logging**: Review real-time output

### After Running
1. **Restart**: Reboot applications as needed
2. **Verification**: Test application functionality
3. **Re-authentication**: Login to affected applications
4. **Monitoring**: Watch for token recreation

## Legal and Ethical Considerations

### Authorized Use Only
- Use only on systems you own or have explicit permission to modify
- Follow organizational security policies
- Comply with applicable laws and regulations
- Respect user privacy and data protection requirements

### Audit Trail
- The script generates comprehensive logs
- All actions are recorded with timestamps
- Consider archiving logs for compliance
- Document the purpose and authorization for execution

## Advanced Configuration

### Custom Token Patterns
To add custom token patterns, modify the `$TokenPatterns` hash table in the script:

```powershell
$TokenPatterns = @{
    'Custom' = @(
        'your_custom_pattern_here'
    )
}
```

### Exclude Paths
Modify the file search patterns to exclude specific directories:

```powershell
# Add to any file search pattern
| Where-Object { $_.FullName -notmatch 'excluded_path' }
```

### Custom Wipe Methods
Extend the `Secure-WipeFile` function to implement additional sanitization methods:

```powershell
# Add custom sanitization logic
switch ($WipeMethod) {
    'NIST80088' { # Current implementation }
    'DoD5220' { # Legacy 3-pass method }
    'Gutmann' { # 35-pass method }
}
```

## Support and Maintenance

### Updates
- Review token patterns for new applications
- Update file paths as applications evolve
- Monitor for new authentication methods
- Test compatibility with OS updates

### Compatibility
- Windows 10/11
- Windows Server 2016/2019/2022
- PowerShell 5.1+
- .NET Framework 4.7.2+

### Known Limitations
- Cannot access in-memory tokens directly
- Some files may be in use during scan
- Application-specific token formats may not be recognized
- Network-based tokens not accessible

For additional support or to report issues, review the log file and console output for specific error messages.