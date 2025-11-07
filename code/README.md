# AppTokenEraser - Application Token and Credential Erasure Tool

A comprehensive PowerShell tool for identifying, extracting, and securely deleting application tokens and credentials from various software applications. Based on evidence-backed research from security documentation and implementing NIST 800-88 aligned secure deletion methods.

## Overview

This tool targets application tokens and credentials for gaming platforms, communication apps, creative software, and developer tools. It uses exact file paths and registry keys from security research to provide comprehensive token erasure with secure deletion capabilities.

## Files Included

### 1. AppTokenEraser.ps1 (Main Script)
**Purpose**: Core token erasure tool for production use

**Features**:
- **Comprehensive Application Coverage**:
  - Gaming: Steam, Epic Games (EOS), Battle.net, Origin (EA App), Ubisoft Connect
  - Communication: Discord
  - Streaming: Spotify
  - Creative: Adobe Creative Cloud
  - Productivity: Office 365, Microsoft Store apps
  - Development: GitHub, GitLab, Visual Studio Code
  - Optional: Chrome, Edge, Firefox browser data

- **Advanced Token Detection**:
  - OAuth tokens (access_token, refresh_token, auth_token)
  - JSON Web Tokens (JWT) with validation
  - Personal Access Tokens (PATs) for GitHub, GitLab, and other services
  - Session tokens and authentication cookies
  - Base64 and hexadecimal encoded credentials

- **Storage Location Targeting**:
  - Application data directories (.json, .xml, .ini, .vdf, .db files)
  - LevelDB databases (Discord and other Electron apps)
  - Registry keys for stored credentials
  - Windows Credential Manager integration
  - Browser storage scanning

- **Security Features**:
  - NIST SP 800-88 compliant secure deletion
  - Multi-pass overwriting (configurable)
  - Cryptographic random data generation
  - Comprehensive logging and audit trail

### 2. Test-AppTokenEraser.ps1 (Test Script)
**Purpose**: Safe testing and demonstration tool

**Features**:
- Creates realistic test token data
- Validates pattern detection without destructive changes
- Simulates file system and registry scanning
- Tests Windows Credential Manager integration
- Generates comprehensive test reports

### 3. AppTokenEraser_UsageGuide.md
**Purpose**: Complete usage documentation

**Contents**:
- Detailed parameter reference and examples
- Safety considerations and best practices
- Troubleshooting guide
- Legal and ethical considerations
- Advanced configuration options

## Quick Start

### Basic Usage
```powershell
# Run in dry-run mode (safe testing)
.\AppTokenEraser.ps1 -DryRun -Verbose

# Perform token erasure with secure deletion
.\AppTokenEraser.ps1 -SecureWipe -WipePasses 3

# Include browser data in scan
.\AppTokenEraser.ps1 -IncludeBrowserData -Verbose
```

### Testing
```powershell
# Run test suite with test data generation
.\Test-AppTokenEraser.ps1 -GenerateTestData -TestMode all

# Test specific components
.\Test-AppTokenEraser.ps1 -TestMode patterns
```

## Prerequisites

- Windows PowerShell 5.1 or later
- Administrator privileges (required for registry and system access)
- .NET Framework 4.7.2 or later

## Supported Applications and Token Types

### Gaming Platforms
- **Steam**: Session tokens, configuration data
- **Epic Games/EOS**: Refresh tokens in OS credential store
- **Battle.net**: Client configuration and registry data
- **Origin (EA App)**: Account authentication data
- **Ubisoft Connect**: Login tokens and configuration

### Communication & Streaming
- **Discord**: LevelDB authentication tokens
- **Spotify**: OAuth tokens and refresh tokens

### Creative & Productivity
- **Adobe Creative Cloud**: OAuth tokens and client credentials
- **Office 365**: Microsoft identity platform tokens
- **Microsoft Store Apps**: App-specific tokens

### Development Tools
- **GitHub**: Personal Access Tokens (PATs)
- **GitLab**: PATs and OAuth tokens
- **Visual Studio Code**: Git credentials and extension tokens

### Browsers (Optional)
- **Chrome**: localStorage, sessionStorage, cookies
- **Edge**: Chromium-based storage
- **Firefox**: Browser storage data

## Token Detection Patterns

The tool uses sophisticated pattern matching to identify various token formats:

- **OAuth Tokens**: `access_token=`, `refresh_token=`, `auth_token=`
- **JWT**: Base64 encoded with proper structure validation
- **PATs**: Service-specific patterns (GitHub, GitLab, Discord)
- **Session Tokens**: Various authentication session formats
- **Base64/Hex**: Encoded credential formats

## Security Standards Compliance

### NIST SP 800-88 Alignment
- **Clear**: Single-pass overwrite for HDDs
- **Purge**: Multi-pass overwriting for sensitive data
- **Verification**: Post-deletion verification
- **Documentation**: Comprehensive audit trail

### Secure Deletion Methods
- **Random Data Overwriting**: Cryptographically secure random data
- **Multiple Passes**: Configurable pass count (1-7)
- **File Size Optimization**: Efficient handling of large files
- **Error Recovery**: Graceful failure handling

## Usage Examples

### Basic Token Scan
```powershell
# Safe scanning without modifications
.\AppTokenEraser.ps1 -DryRun

# Detailed scanning with verbose output
.\AppTokenEraser.ps1 -Verbose
```

### Secure Token Erasure
```powershell
# Standard secure deletion
.\AppTokenEraser.ps1 -SecureWipe

# High-security 3-pass deletion
.\AppTokenEraser.ps1 -SecureWipe -WipePasses 3
```

### Targeted Scanning
```powershell
# Include browser data in scan
.\AppTokenEraser.ps1 -IncludeBrowserData

# Full scan with all options
.\AppTokenEraser.ps1 -IncludeBrowserData -SecureWipe -Verbose
```

## Safety Features

### Dry Run Mode
- No actual file modifications
- Comprehensive logging of proposed actions
- Safe for testing and validation

### Administrator Requirements
- Registry access requires admin rights
- Secure deletion needs elevated permissions
- Prevents unauthorized credential access

### Error Handling
- Graceful failure recovery
- Detailed error logging
- Continues operation on non-critical failures

## File System Locations

### Application Data
```
Steam:          %LOCALAPPDATA%\Steam\config\
Discord:        %LOCALAPPDATA%\Discord\app-*\Local Storage\leveldb\
Spotify:        %LOCALAPPDATA%\Spotify\storage\
Epic Games:     %LOCALAPPDATA%\EpicGamesLauncher\
Battle.net:     %LOCALAPPDATA%\Battle.net\
Adobe CC:       %LOCALAPPDATA%\Adobe\
GitHub:         %USERPROFILE%\.gitconfig\
VS Code:        %APPDATA%\Code\User\
```

### Registry Keys
```
Steam:          HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam
Battle.net:     HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Battle.net
Windows Creds:  Credential Manager entries
```

## Logging and Audit Trail

### Log File Location
- **Primary**: `%TEMP%\AppTokenEraser_YYYYMMDD_HHMMSS.log`
- **Format**: Comprehensive with timestamps and severity levels
- **Content**: Token discoveries, deletions, errors, final report

### Report Contents
- Total tokens found and types
- Items successfully erased
- Items that failed processing
- Recommendations for follow-up actions

## Testing and Validation

### Test Script Features
```powershell
# Create test data and run pattern detection
.\Test-AppTokenEraser.ps1 -GenerateTestData -TestMode patterns

# Complete test suite
.\Test-AppTokenEraser.ps1 -TestMode all

# Specific component testing
.\Test-AppTokenEraser.ps1 -TestMode filesystem
.\Test-AppTokenEraser.ps1 -TestMode registry
.\Test-AppTokenEraser.ps1 -TestMode credentials
```

### Test Data
The test script creates realistic examples:
- Steam configuration with JWT and session tokens
- Discord JSON with OAuth tokens
- GitHub PAT configuration
- Spotify OAuth token response

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

## Troubleshooting

### Common Issues

#### Access Denied Errors
```powershell
# Ensure running as Administrator
# Check file/folder permissions
# Temporarily disable antivirus
# Close applications that might be locking files
```

#### No Tokens Found
- Normal if applications don't store tokens locally
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

## Performance Characteristics

### Scanning Speed
- **Fast scanning**: Optimized pattern matching
- **Parallel processing**: Multiple file types simultaneously
- **Memory efficient**: Streaming file reading for large files

### Storage Impact
- **Minimal disk space**: No temporary file creation
- **No data duplication**: Direct analysis and deletion
- **Recovery prevention**: Secure deletion prevents recovery

## Compliance Support

### NIST SP 800-88
- Provides Clear/Purge/Destroy methodology
- Single-pass overwrites for HDDs
- Cryptographic erasure for SSDs
- Verification requirements

### Industry Standards
- MITRE ATT&CK technique alignment
- Security best practice implementation
- Audit trail maintenance
- Compliance reporting support

## Maintenance and Updates

### Regular Updates
- Token pattern updates for new formats
- Application version compatibility
- Path updates for new application releases
- Security research integration

### Customization
- Add custom token patterns
- Modify target applications
- Configure deletion methods
- Extend logging capabilities

## Support and Documentation

For detailed information:
1. Review `AppTokenEraser_UsageGuide.md` for comprehensive usage instructions
2. Check log files for specific error messages
3. Use test script to validate functionality
4. Follow best practices for safe operation

## Disclaimer

This tool performs irreversible data deletion. Users must ensure they have proper authorization and backups before using this tool. The authors are not responsible for any data loss or compliance issues arising from use of this software.

---

**⚠️ WARNING: This tool performs irreversible data deletion. Always verify you have proper authorization and backups before proceeding.**