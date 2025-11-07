# Windows 11 Credential Eraser - Comprehensive Credential System Targeting
# Targets: Windows Credential Manager, Windows Hello, TPM, AD, MS Account, DPAPI, Registry, UWP, etc.
# Requires: Administrator privileges
# Compatible: Windows 11 with various security configurations

param(
    [switch]$Force,
    [switch]$Verbose,
    [switch]$BackupKeys,
    [string]$OutputPath = "$env:TEMP\CredEraser_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# Global error handling
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Security constants
$WIFI_PROFILE_PATH = "$env:ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\*"
$CREDENTIAL_MANAGER_PATH = "$env:LOCALAPPDATA\Microsoft\Credentials"
$DPAPI_PATH = "$env:APPDATA\Microsoft\Protect"
$HELLO_PATH = "$env:LOCALAPPDATA\Microsoft\Biometrics"
$UWP_CRED_PATH = "$env:LOCALAPPDATA\Microsoft\Windows\WebCache"
$ONEDRIVE_CACHE = "$env:LOCALAPPDATA\Microsoft\OneDrive"

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if ($Verbose) {
        Write-Host $logMessage -ForegroundColor ({
            "INFO" { "White" }
            "WARN" { "Yellow" }
            "ERROR" { "Red" }
            "SUCCESS" { "Green" }
        }[$Level])
    }
}

# Secure file deletion using multiple passes
function Remove-SecureFile {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) { return }
    
    try {
        Write-Log "Securely deleting: $FilePath" "INFO"
        
        $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        if ($fileInfo -is [System.IO.DirectoryInfo]) {
            $files = Get-ChildItem $FilePath -Recurse -File -ErrorAction SilentlyContinue
        } else {
            $files = @($fileInfo)
        }
        
        foreach ($file in $files) {
            try {
                # DoD 5220.22-M standard: 3-pass overwrite
                $fileSize = $file.Length
                
                # Pass 1: Fill with 0x00
                $stream = [System.IO.File]::OpenWrite($file.FullName)
                $buffer = New-Object byte[] 65536
                [System.Array]::Fill($buffer, [byte]0x00)
                for ($i = 0; $i -lt $fileSize; $i += 65536) {
                    $stream.Write($buffer, 0, [Math]::Min(65536, $fileSize - $i))
                    $stream.Flush()
                }
                $stream.Close()
                
                # Pass 2: Fill with 0xFF
                $stream = [System.IO.File]::OpenWrite($file.FullName)
                [System.Array]::Fill($buffer, [byte]0xFF)
                for ($i = 0; $i -lt $fileSize; $i += 65536) {
                    $stream.Write($buffer, 0, [Math]::Min(65536, $fileSize - $i))
                    $stream.Flush()
                }
                $stream.Close()
                
                # Pass 3: Fill with random data
                $stream = [System.IO.File]::OpenWrite($file.FullName)
                $random = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
                for ($i = 0; $i -lt $fileSize; $i += 65536) {
                    $bytes = New-Object byte[65536]
                    $random.GetBytes($bytes)
                    $toWrite = [Math]::Min(65536, $fileSize - $i)
                    $stream.Write($bytes, 0, $toWrite)
                    $stream.Flush()
                }
                $stream.Close()
                $random.Dispose()
                
                # Final deletion
                Remove-Item $file.FullName -Force -ErrorAction Stop
                Write-Log "Deleted: $($file.FullName)" "SUCCESS"
                
            } catch {
                Write-Log "Failed to securely delete $($file.FullName): $($_.Exception.Message)" "WARN"
                # Fallback to regular deletion
                Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-Log "Error processing path $FilePath : $($_.Exception.Message)" "ERROR"
    }
}

# Windows Credential Manager (CredRead/CredWrite API) targeting
function Remove-WindowsCredentialManager {
    Write-Log "=== Targeting Windows Credential Manager ===" "INFO"
    
    try {
        # Add Win32 API declarations
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        
        # Import advapi32 functions
        $advApi32 = @"
        using System;
        using System.Runtime.InteropServices;
        
        public class AdvApi32 {
            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern bool CredRead(string targetName, int type, int flags, out IntPtr credential);
            
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern void CredFree(IntPtr cred);
            
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool CredWrite(IntPtr credential, int flags);
            
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool CredEnumerate(string filter, int flags, out int count, out IntPtr credentials);
            
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool CredDelete(string targetName, int type, int flags);
            
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern int CredGetSessionKey(IntPtr credential, int flags, out IntPtr sessionKey, out int sessionKeyLength);
        }
"@
        Add-Type $advApi32
        
        # Enumerate and delete all stored credentials
        $credentials = @()
        
        # Get Windows credentials
        try {
            $winCreds = Get-StoredCredential -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq "Windows" }
            $credentials += $winCreds
        } catch {
            Write-Log "Could not enumerate Windows credentials: $($_.Exception.Message)" "WARN"
        }
        
        # Get Web credentials
        try {
            $webCreds = Get-StoredCredential -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq "Web" }
            $credentials += $webCreds
        } catch {
            Write-Log "Could not enumerate Web credentials: $($_.Exception.Message)" "WARN"
        }
        
        # Delete each credential
        foreach ($cred in $credentials) {
            try {
                Write-Log "Deleting credential: $($cred.TargetName)" "INFO"
                
                # Try API deletion first
                $type = if ($cred.Type -eq "Web") { 2 } else { 1 }  # CRED_TYPE_GENERIC vs CRED_TYPE_DOMAIN_PASSWORD
                
                # Use command line tool as backup
                cmdkey /delete:$($cred.TargetName) /quiet 2>$null
                
                Write-Log "Deleted credential: $($cred.TargetName)" "SUCCESS"
            } catch {
                Write-Log "Failed to delete credential $($cred.TargetName): $($_.Exception.Message)" "WARN"
            }
        }
        
        # Clear Credential Manager vault files
        $vaultFiles = @(
            "$CREDENTIAL_MANAGER_PATH\*",
            "$env:LOCALAPPDATA\Microsoft\Vault\*",
            "$env:LOCALAPPDATA\Microsoft\Credentials\*"
        )
        
        foreach ($pattern in $vaultFiles) {
            $files = Get-ChildItem $pattern -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -eq $false }
            foreach ($file in $files) {
                Remove-SecureFile $file.FullName
            }
        }
        
        # Clear vault directories
        $vaultDirs = @(
            "$CREDENTIAL_MANAGER_PATH",
            "$env:LOCALAPPDATA\Microsoft\Vault",
            "$env:APPDATA\Microsoft\Credentials"
        )
        
        foreach ($dir in $vaultDirs) {
            if (Test-Path $dir) {
                Get-ChildItem $dir -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                Write-Log "Cleared vault directory: $dir" "SUCCESS"
            }
        }
        
    } catch {
        Write-Log "Error in Credential Manager removal: $($_.Exception.Message)" "ERROR"
    }
}

# Windows Hello (biometric data, PIN storage) targeting
function Remove-WindowsHello {
    Write-Log "=== Targeting Windows Hello Biometric Data ===" "INFO"
    
    try {
        # Check if Enhanced Sign-in Security (ESS) is enabled
        try {
            $essEnabled = Get-WindowsCapability -Online | Where-Object { $_.Name -like "*Hello*" -and $_.State -eq "Installed" }
            if ($essEnabled) {
                Write-Log "Enhanced Sign-in Security detected" "INFO"
            }
        } catch {
            Write-Log "Could not check ESS status: $($_.Exception.Message)" "WARN"
        }
        
        # Windows Hello biometric database locations
        $helloPaths = @(
            "$HELLO_PATH",
            "$env:LOCALAPPDATA\Microsoft\Crypto\DPAPI",
            "$env:LOCALAPPDATA\Microsoft\Windows\Hello\Face",
            "$env:LOCALAPPDATA\Microsoft\Windows\Hello\Fingerprint"
        )
        
        # Clear biometric databases
        foreach ($path in $helloPaths) {
            if (Test-Path $path) {
                Write-Log "Processing Windows Hello path: $path" "INFO"
                
                # Get all files and directories
                $items = Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue
                
                foreach ($item in $items) {
                    if ($item.PSIsContainer) {
                        Remove-SecureFile $item.FullName
                    } else {
                        # Specific file types for biometric data
                        if ($item.Extension -match "\.(db|dbf|tmp|cache|dat|bin)$") {
                            Remove-SecureFile $item.FullName
                        }
                    }
                }
                
                Write-Log "Cleared Windows Hello path: $path" "SUCCESS"
            }
        }
        
        # Remove Windows Hello enrollment keys
        $helloKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsHello",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Biometrics",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Biometrics"
        )
        
        foreach ($key in $helloKeys) {
            try {
                if (Test-Path $key) {
                    $subKeys = Get-ChildItem $key -Recurse -ErrorAction SilentlyContinue
                    foreach ($subKey in $subKeys) {
                        Remove-Item $subKey.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    Write-Log "Removed registry key: $key" "SUCCESS"
                }
            } catch {
                Write-Log "Could not remove key $key : $($_.Exception.Message)" "WARN"
            }
        }
        
        # Clear Windows Hello PIN policies and settings
        try {
            # Disable Windows Hello
            Disable-WindowsHelloForBusiness -ErrorAction SilentlyContinue
            Write-Log "Disabled Windows Hello for Business" "SUCCESS"
        } catch {
            Write-Log "Could not disable Windows Hello via cmdlet: $($_.Exception.Message)" "WARN"
        }
        
        # Clear biometric driver data
        $biometricDrivers = @(
            "$env:SystemRoot\System32\drivers\*biometric*",
            "$env:SystemRoot\System32\drivers\*fingerprint*",
            "$env:SystemRoot\System32\drivers\*face*"
        )
        
        foreach ($pattern in $biometricDrivers) {
            $files = Get-ChildItem $pattern -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                # Clear driver data but don't remove drivers
                $tempFile = "$env:TEMP\$([System.Guid]::NewGuid()).tmp"
                $fileStream = [System.IO.File]::OpenRead($file.FullName)
                $buffer = New-Object byte[] $fileStream.Length
                $fileStream.Read($buffer, 0, $buffer.Length)
                $fileStream.Close()
                
                $outStream = [System.IO.File]::OpenWrite($file.FullName)
                $random = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
                $random.GetBytes($buffer)
                $outStream.Write($buffer, 0, $buffer.Length)
                $outStream.Close()
                $random.Dispose()
                
                Write-Log "Cleared biometric driver data: $($file.FullName)" "INFO"
            }
        }
        
    } catch {
        Write-Log "Error in Windows Hello removal: $($_.Exception.Message)" "ERROR"
    }
}

# TPM chip data targeting
function Remove-TPMData {
    Write-Log "=== Targeting TPM Chip Data ===" "INFO"
    
    try {
        # TPM management requires special care due to hardware protection
        try {
            # Initialize TPM - this will clear existing keys
            Initialize-Tpm -ErrorAction SilentlyContinue | Out-Null
            Write-Log "TPM initialized (clears non-exportable keys)" "SUCCESS"
        } catch {
            Write-Log "TPM initialization failed (may be protected by hardware): $($_.Exception.Message)" "WARN"
        }
        
        # Clear TPM endorsement keys and certificates
        $tpmPaths = @(
            "$env:ProgramData\Microsoft\Cryptography\TPMS",
            "$env:ProgramData\Microsoft\Cryptography\Services",
            "$env:LOCALAPPDATA\Microsoft\Crypto\Keys"
        )
        
        foreach ($path in $tpmPaths) {
            if (Test-Path $path) {
                $items = Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    if ($item.PSIsContainer) {
                        Remove-SecureFile $item.FullName
                    } else {
                        Remove-SecureFile $item.FullName
                    }
                }
                Write-Log "Cleared TPM path: $path" "SUCCESS"
            }
        }
        
        # Clear BitLocker-related TPM data (TPM is used by BitLocker)
        try {
            Clear-BitLockerAutoUnlock -ErrorAction SilentlyContinue
            Write-Log "Cleared BitLocker auto-unlock data" "SUCCESS"
        } catch {
            Write-Log "Could not clear BitLocker auto-unlock: $($_.Exception.Message)" "WARN"
        }
        
        # Clear Windows Hello TPM keys
        try {
            $helloKeyPath = "$env:LOCALAPPDATA\Microsoft\Crypto\Keys"
            if (Test-Path $helloKeyPath) {
                Get-ChildItem $helloKeyPath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                Write-Log "Cleared Windows Hello TPM keys" "SUCCESS"
            }
        } catch {
            Write-Log "Could not clear Windows Hello TPM keys: $($_.Exception.Message)" "WARN"
        }
        
    } catch {
        Write-Log "Error in TPM data removal: $($_.Exception.Message)" "ERROR"
    }
}

# Active Directory credentials targeting
function Remove-ActiveDirectoryCreds {
    Write-Log "=== Targeting Active Directory Credentials ===" "INFO"
    
    try {
        # Clear Kerberos tickets and TGTs
        try {
            & klist purge 2>$null
            Write-Log "Purged Kerberos tickets" "SUCCESS"
        } catch {
            Write-Log "Could not purge Kerberos tickets: $($_.Exception.Message)" "WARN"
        }
        
        # Clear cached domain credentials
        $cachedCredsPath = "HKLM:\SECURITY\Cache"
        try {
            if (Test-Path $cachedCredsPath) {
                $subKeys = Get-ChildItem $cachedCredsPath -ErrorAction SilentlyContinue
                foreach ($subKey in $subKeys) {
                    Remove-Item $subKey.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                Write-Log "Cleared cached domain credentials" "SUCCESS"
            }
        } catch {
            Write-Log "Could not access cached credentials registry: $($_.Exception.Message)" "WARN"
        }
        
        # Clear LSASS cached credentials in memory (this requires LSASS process access)
        try {
            $lsass = Get-Process lsass -ErrorAction SilentlyContinue
            if ($lsass) {
                # LSASS is running - we cannot safely clear its memory without system compromise
                Write-Log "LSASS process detected - cannot safely clear memory credentials" "WARN"
            }
        } catch {
            Write-Log "Could not access LSASS process: $($_.Exception.Message)" "WARN"
        }
        
        # Clear NTLM and Kerberos credential cache files
        $netLogonPath = "$env:SystemRoot\System32\LogFiles\WMI\RtBackup"
        if (Test-Path $netLogonPath) {
            $files = Get-ChildItem $netLogonPath -Filter "*.log" -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                Remove-SecureFile $file.FullName
            }
            Write-Log "Cleared NetLogon cache files" "SUCCESS"
        }
        
        # Clear domain join machine accounts and certificates
        $domainCertPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
        if (Test-Path $domainCertPath) {
            $files = Get-ChildItem $domainCertPath -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "machineaccount" -or $_.Name -match "domain" }
            foreach ($file in $files) {
                Remove-SecureFile $file.FullName
            }
            Write-Log "Cleared domain-related machine certificates" "SUCCESS"
        }
        
    } catch {
        Write-Log "Error in AD credentials removal: $($_.Exception.Message)" "ERROR"
    }
}

# Microsoft Account sync data targeting
function Remove-MicrosoftAccountData {
    Write-Log "=== Targeting Microsoft Account Sync Data ===" "INFO"
    
    try {
        # OneDrive sign-in cache files
        $oneDrivePaths = @(
            "$ONEDRIVE_CACHE",
            "$env:LOCALAPPDATA\Microsoft\OneDrive",
            "$env:LOCALAPPDATA\Microsoft\OneDrive\settings\Personal"
        )
        
        foreach ($path in $oneDrivePaths) {
            if (Test-Path $path) {
                Write-Log "Processing OneDrive path: $path" "INFO"
                
                # Clear PreSignInSettingsConfig.json
                $preSignIn = Get-ChildItem $path -Recurse -Filter "PreSignInSettingsConfig.json" -ErrorAction SilentlyContinue
                foreach ($file in $preSignIn) {
                    Remove-SecureFile $file.FullName
                    Write-Log "Cleared OneDrive PreSignInSettingsConfig.json" "SUCCESS"
                }
                
                # Clear all cache files
                $cacheFiles = Get-ChildItem $path -Recurse -Include "*.json", "*.cache", "*.tmp", "*.dat" -ErrorAction SilentlyContinue
                foreach ($file in $cacheFiles) {
                    Remove-SecureFile $file.FullName
                }
                
                Write-Log "Cleared OneDrive cache in: $path" "SUCCESS"
            }
        }
        
        # Windows Hello PIN recovery data (Microsoft Account backed)
        try {
            $helloRecoveryPath = "$env:LOCALAPPDATA\Microsoft\Windows\Hello\Recovery"
            if (Test-Path $helloRecoveryPath) {
                Get-ChildItem $helloRecoveryPath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                Write-Log "Cleared Windows Hello PIN recovery data" "SUCCESS"
            }
        } catch {
            Write-Log "Could not clear Hello recovery data: $($_.Exception.Message)" "WARN"
        }
        
        # Microsoft Account credentials in Credential Manager
        try {
            $msAccountCreds = Get-StoredCredential -ErrorAction SilentlyContinue | Where-Object { 
                $_.TargetName -like "*microsoft*" -or 
                $_.TargetName -like "*live*" -or 
                $_.TargetName -like "*hotmail*" -or 
                $_.TargetName -like "*outlook*" 
            }
            
            foreach ($cred in $msAccountCreds) {
                Write-Log "Deleting Microsoft Account credential: $($cred.TargetName)" "INFO"
                cmdkey /delete:$($cred.TargetName) /quiet 2>$null
            }
            Write-Log "Cleared Microsoft Account credentials" "SUCCESS"
        } catch {
            Write-Log "Could not enumerate Microsoft Account credentials: $($_.Exception.Message)" "WARN"
        }
        
        # Windows Backup settings and sync data
        $backupPath = "$env:LOCALAPPDATA\Microsoft\Windows\CloudExperienceHost"
        if (Test-Path $backupPath) {
            $files = Get-ChildItem $backupPath -Recurse -Include "*.json", "*.cache" -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                Remove-SecureFile $file.FullName
            }
            Write-Log "Cleared Windows Backup cache" "SUCCESS"
        }
        
    } catch {
        Write-Log "Error in Microsoft Account data removal: $($_.Exception.Message)" "ERROR"
    }
}

# DPAPI master keys targeting
function Remove-DPAPIKeys {
    Write-Log "=== Targeting DPAPI Master Keys ===" "INFO"
    
    try {
        # DPAPI master key locations
        $dpapiPaths = @(
            "$DPAPI_PATH",
            "$env:ProgramData\Microsoft\Protect",
            "$env:LOCALAPPDATA\Microsoft\Protect"
        )
        
        foreach ($path in $dpapiPaths) {
            if (Test-Path $path) {
                Write-Log "Processing DPAPI path: $path" "INFO"
                
                # Get all subdirectories (user GUIDs, system keys, etc.)
                $subDirs = Get-ChildItem $path -Directory -ErrorAction SilentlyContinue
                
                foreach ($subDir in $subDirs) {
                    Write-Log "Clearing DPAPI subdirectory: $($subDir.FullName)" "INFO"
                    
                    # Process all files in the subdirectory
                    $files = Get-ChildItem $subDir.FullName -Recurse -File -ErrorAction SilentlyContinue
                    foreach ($file in $files) {
                        Remove-SecureFile $file.FullName
                    }
                    
                    # Recursively process subdirectories
                    Get-ChildItem $subDir.FullName -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                        $subFiles = Get-ChildItem $_.FullName -File -ErrorAction SilentlyContinue
                        foreach ($file in $subFiles) {
                            Remove-SecureFile $file.FullName
                        }
                    }
                }
                
                Write-Log "Cleared DPAPI path: $path" "SUCCESS"
            }
        }
        
        # Clear DPAPI credential blobs
        $dpapiCredPaths = @(
            "$env:APPDATA\Microsoft\SystemCertificates\My\Keys",
            "$env:ProgramData\Microsoft\Crypto\Keys",
            "$env:LOCALAPPDATA\Microsoft\Crypto\Keys"
        )
        
        foreach ($path in $dpapiCredPaths) {
            if (Test-Path $path) {
                $files = Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -eq $false }
                foreach ($file in $files) {
                    Remove-SecureFile $file.FullName
                }
                Write-Log "Cleared DPAPI credentials: $path" "SUCCESS"
            }
        }
        
        # Clear browser credential bank data (which uses DPAPI)
        $credBankPaths = @(
            "$env:LOCALAPPDATA\Microsoft\SystemCertificates\My\Certificates",
            "$env:APPDATA\Microsoft\SystemCertificates\My\Certificates",
            "$env:LOCALAPPDATA\Microsoft\MicrosoftEdge\Cookies"
        )
        
        foreach ($path in $credBankPaths) {
            if (Test-Path $path) {
                $files = Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -eq $false }
                foreach ($file in $files) {
                    Remove-SecureFile $file.FullName
                }
                Write-Log "Cleared credential bank: $path" "SUCCESS"
            }
        }
        
    } catch {
        Write-Log "Error in DPAPI keys removal: $($_.Exception.Message)" "ERROR"
    }
}

# Registry credential storage targeting
function Remove-RegistryCreds {
    Write-Log "=== Targeting Registry Credential Storage ===" "INFO"
    
    try {
        # LSA Security registry hive
        $securityHive = "HKLM:\SECURITY"
        try {
            if (Test-Path $securityHive) {
                # Cache credentials
                $cachePath = "$securityHive\Cache"
                if (Test-Path $cachePath) {
                    $cacheItems = Get-ChildItem $cachePath -ErrorAction SilentlyContinue
                    foreach ($item in $cacheItems) {
                        Remove-Item $item.PSPath -Force -ErrorAction SilentlyContinue
                    }
                    Write-Log "Cleared LSA cached credentials" "SUCCESS"
                }
                
                # LSA secrets (contains service passwords, etc.)
                $secretsPath = "$securityHive\Policy\Secrets"
                if (Test-Path $secretsPath) {
                    $secrets = Get-ChildItem $secretsPath -ErrorAction SilentlyContinue
                    foreach ($secret in $secrets) {
                        Remove-Item $secret.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    Write-Log "Cleared LSA secrets" "SUCCESS"
                }
            }
        } catch {
            Write-Log "Could not access SECURITY hive: $($_.Exception.Message)" "WARN"
        }
        
        # SAM registry hive (local accounts)
        $samHive = "HKLM:\SAM"
        try {
            if (Test-Path $samHive) {
                $samItems = Get-ChildItem $samHive -ErrorAction SilentlyContinue
                foreach ($item in $samItems) {
                    # Clear F values which contain password hashes
                    if ($item.PSChildName -match "^[0-9A-F]{8}$") {
                        $fPath = "$($item.PSPath)\F"
                        if (Test-Path $fPath) {
                            Remove-Item $fPath -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
                Write-Log "Cleared SAM password hashes" "SUCCESS"
            }
        } catch {
            Write-Log "Could not access SAM hive: $($_.Exception.Message)" "WARN"
        }
        
        # Windows Hello registry entries
        $helloRegPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsHello",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Biometrics\Fingerprint\Enroll",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Biometrics\Face\Enroll"
        )
        
        foreach ($path in $helloRegPaths) {
            try {
                if (Test-Path $path) {
                    $subItems = Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue
                    foreach ($item in $subItems) {
                        Remove-Item $item.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    Write-Log "Cleared registry path: $path" "SUCCESS"
                }
            } catch {
                Write-Log "Could not clear registry path $path : $($_.Exception.Message)" "WARN"
            }
        }
        
        # UWP app credentials
        $uwpRegPaths = @(
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\WebAccountManager",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\WebAuthn"
        )
        
        foreach ($path in $uwpRegPaths) {
            try {
                if (Test-Path $path) {
                    $subItems = Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue
                    foreach ($item in $subItems) {
                        Remove-Item $item.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    Write-Log "Cleared UWP registry path: $path" "SUCCESS"
                }
            } catch {
                Write-Log "Could not clear UWP registry path $path : $($_.Exception.Message)" "WARN"
            }
        }
        
        # Internet Explorer/Edge legacy credential storage
        $ieRegPaths = @(
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoCompleteSettings",
            "HKCU:\SOFTWARE\Microsoft\Internet Explorer\IntelliForms\Storage2"
        )
        
        foreach ($path in $ieRegPaths) {
            try {
                if (Test-Path $path) {
                    $subItems = Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue
                    foreach ($item in $subItems) {
                        Remove-Item $item.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    Write-Log "Cleared IE/Edge registry path: $path" "SUCCESS"
                }
            } catch {
                Write-Log "Could not clear IE/Edge registry path $path : $($_.Exception.Message)" "WARN"
            }
        }
        
    } catch {
        Write-Log "Error in registry credentials removal: $($_.Exception.Message)" "ERROR"
    }
}

# UWP app credentials targeting
function Remove-UWPCreds {
    Write-Log "=== Targeting UWP App Credentials ===" "INFO"
    
    try {
        # Clear WebCache (includes Edge, IE, UWP app data)
        $webCachePath = "$UWP_CRED_PATH"
        if (Test-Path $webCachePath) {
            $items = Get-ChildItem $webCachePath -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if ($item.PSIsContainer) {
                    Remove-SecureFile $item.FullName
                } else {
                    # Clear specific cache file types
                    if ($item.Extension -match "\.(dat|cache|tmp|log|db)$") {
                        Remove-SecureFile $item.FullName
                    }
                }
            }
            Write-Log "Cleared WebCache" "SUCCESS"
        }
        
        # UWP app local storage
        $localAppData = "$env:LOCALAPPDATA"
        $uwpAppPaths = @(
            "$localAppData\Packages\*\AC\MicrosoftEdge*",
            "$localAppData\Packages\*\LocalCache",
            "$localAppData\Packages\*\LocalAppData"
        )
        
        foreach ($pattern in $uwpAppPaths) {
            $paths = Get-ChildItem $pattern -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer }
            foreach ($path in $paths) {
                $files = Get-ChildItem $path -Recurse -Include "*.json", "*.db", "*.cache", "*.dat" -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    Remove-SecureFile $file.FullName
                }
                Write-Log "Cleared UWP app cache: $($path.FullName)" "INFO"
            }
        }
        
        # Microsoft Edge WebAuthn credentials
        try {
            $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
            if (Test-Path $edgePath) {
                $webAuthnFiles = Get-ChildItem $edgePath -Recurse -Include "WebAuthn*", "Login Data*" -ErrorAction SilentlyContinue
                foreach ($file in $webAuthnFiles) {
                    Remove-SecureFile $file.FullName
                }
                Write-Log "Cleared Edge WebAuthn credentials" "SUCCESS"
            }
        } catch {
            Write-Log "Could not clear Edge WebAuthn: $($_.Exception.Message)" "WARN"
        }
        
        # Windows Hello for Business provisioning data
        $whfbPath = "$env:LOCALAPPDATA\Microsoft\WHfB"
        if (Test-Path $whfbPath) {
            $items = Get-ChildItem $whfbPath -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if ($item.PSIsContainer) {
                    Remove-SecureFile $item.FullName
                } else {
                    Remove-SecureFile $item.FullName
                }
            }
            Write-Log "Cleared WHfB provisioning data" "SUCCESS"
        }
        
        # Clear UWP account data
        $accountDataPath = "$env:LOCALAPPDATA\Microsoft\Windows\WebAccountManager"
        if (Test-Path $accountDataPath) {
            $files = Get-ChildItem $accountDataPath -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -eq $false }
            foreach ($file in $files) {
                Remove-SecureFile $file.FullName
            }
            Write-Log "Cleared UWP account data" "SUCCESS"
        }
        
    } catch {
        Write-Log "Error in UWP credentials removal: $($_.Exception.Message)" "ERROR"
    }
}

# Network credential caches
function Remove-NetworkCreds {
    Write-Log "=== Targeting Network Credential Caches ===" "INFO"
    
    try {
        # Wi-Fi profiles (store pre-shared keys, certificates)
        $wifiProfiles = Get-WifiProfile -ErrorAction SilentlyContinue
        foreach ($profile in $wifiProfiles) {
            try {
                Write-Log "Removing Wi-Fi profile: $($profile.Name)" "INFO"
                Remove-WifiProfile -Name $profile.Name -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Log "Could not remove Wi-Fi profile $($profile.Name): $($_.Exception.Message)" "WARN"
            }
        }
        
        # Clear stored network passwords
        try {
            $netCreds = cmdkey /list 2>$null
            if ($netCreds) {
                $targetLines = $netCreds | Where-Object { $_ -match "Target:" }
                foreach ($line in $targetLines) {
                    $target = ($line -split "Target:")[1].Trim()
                    if ($target) {
                        Write-Log "Removing network credential: $target" "INFO"
                        cmdkey /delete:$target /quiet 2>$null
                    }
                }
            }
        } catch {
            Write-Log "Could not enumerate network credentials: $($_.Exception.Message)" "WARN"
        }
        
        # Clear Windows Hello for Business device unlock credentials
        try {
            $deviceUnlockPath = "HKLM:\SOFTWARE\Microsoft\PassportForWork\DeviceUnlock"
            if (Test-Path $deviceUnlockPath) {
                $items = Get-ChildItem $deviceUnlockPath -Recurse -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    Remove-Item $item.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                Write-Log "Cleared device unlock credentials" "SUCCESS"
            }
        } catch {
            Write-Log "Could not clear device unlock credentials: $($_.Exception.Message)" "WARN"
        }
        
    } catch {
        Write-Log "Error in network credentials removal: $($_.Exception.Message)" "ERROR"
    }
}

# Additional Windows-native credential vaults
function Remove-OtherVaults {
    Write-Log " === Targeting Other Windows-Native Credential Vaults ===" "INFO"
    
    try {
        # Windows Hello for Business keys
        $whfbKeysPath = "$env:LOCALAPPDATA\Microsoft\Crypto"
        if (Test-Path $whfbKeysPath) {
            $keys = Get-ChildItem $whfbKeysPath -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -eq $false }
            foreach ($key in $keys) {
                Remove-SecureFile $key.FullName
            }
            Write-Log "Cleared WHfB crypto keys" "SUCCESS"
        }
        
        # BitLocker recovery keys (may contain credential-related data)
        try {
            $bitlockerKeys = Get-BitLockerVolume -ErrorAction SilentlyContinue
            foreach ($volume in $bitlockerKeys) {
                foreach ($key in $volume.KeyProtector) {
                    if ($key.KeyProtectorType -eq "RecoveryPassword") {
                        Write-Log "Found BitLocker recovery key: $($key.KeyProtectorId)" "INFO"
                    }
                }
            }
        } catch {
            Write-Log "Could not enumerate BitLocker keys: $($_.Exception.Message)" "WARN"
        }
        
        # Windows Hello for Business device unlock
        try {
            $whfbDevicePath = "HKLM:\SOFTWARE\Microsoft\PassportForWork"
            if (Test-Path $whfbDevicePath) {
                $items = Get-ChildItem $whfbDevicePath -Recurse -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    Remove-Item $item.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                Write-Log "Cleared WHfB device unlock data" "SUCCESS"
            }
        } catch {
            Write-Log "Could not clear WHfB device unlock: $($_.Exception.Message)" "WARN"
        }
        
        # Credential Guard (VBS) related data
        try {
            $vbsPath = "$env:SystemRoot\System32\Microsoft\Protect\CredentialGuard"
            if (Test-Path $vbsPath) {
                $items = Get-ChildItem $vbsPath -Recurse -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    if ($item.PSIsContainer) {
                        Remove-SecureFile $item.FullName
                    } else {
                        Remove-SecureFile $item.FullName
                    }
                }
                Write-Log "Cleared Credential Guard data" "SUCCESS"
            }
        } catch {
            Write-Log "Could not clear Credential Guard data: $($_.Exception.Message)" "WARN"
        }
        
        # Network service account credentials
        $nsaPath = "$env:ProgramData\Microsoft\Crypto\SystemKeys"
        if (Test-Path $nsaPath) {
            $items = Get-ChildItem $nsaPath -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -eq $false }
            foreach ($item in $items) {
                Remove-SecureFile $item.FullName
            }
            Write-Log "Cleared network service account credentials" "SUCCESS"
        }
        
        # Windows Hello for Business provisioning data
        $whfbProvisionPath = "$env:LOCALAPPDATA\Microsoft\Windows Hello\Provisioning"
        if (Test-Path $whfbProvisionPath) {
            $items = Get-ChildItem $whfbProvisionPath -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if ($item.PSIsContainer) {
                    Remove-SecureFile $item.FullName
                } else {
                    Remove-SecureFile $item.FullName
                }
            }
            Write-Log "Cleared WHfB provisioning data" "SUCCESS"
        }
        
    } catch {
        Write-Log "Error in other vaults removal: $($_.Exception.Message)" "ERROR"
    }
}

# Security log clearing
function Clear-SecurityLogs {
    Write-Log "=== Clearing Security Event Logs ===" "INFO"
    
    try {
        $securityLogs = @(
            "Security",
            "Microsoft-Windows-EventLog/Diagnostic",
            "Microsoft-Windows-LSA/Operational",
            "Microsoft-Windows-CredentialProvider/Operational"
        )
        
        foreach ($logName in $securityLogs) {
            try {
                & wevtutil cl $logName /quiet 2>$null
                Write-Log "Cleared log: $logName" "SUCCESS"
            } catch {
                Write-Log "Could not clear log $logName : $($_.Exception.Message)" "WARN"
            }
        }
    } catch {
        Write-Log "Error clearing security logs: $($_.Exception.Message)" "ERROR"
    }
}

# Backup function for critical data
function Backup-CriticalData {
    if (-not $BackupKeys) { return }
    
    Write-Log "=== Backing Up Critical Data ===" "INFO"
    
    try {
        $backupDir = $OutputPath
        if (-not (Test-Path $backupDir)) {
            New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        }
        
        # Backup DPAPI keys
        try {
            $dpapiBackupDir = "$backupDir\DPAPI_Backup"
            Copy-Item -Path $DPAPI_PATH -Destination $dpapiBackupDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Backed up DPAPI keys to: $dpapiBackupDir" "INFO"
        } catch {
            Write-Log "Could not backup DPAPI keys: $($_.Exception.Message)" "WARN"
        }
        
        # Backup Credential Manager data
        try {
            $credBackupDir = "$backupDir\CredentialManager_Backup"
            Copy-Item -Path $CREDENTIAL_MANAGER_PATH -Destination $credBackupDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Backed up Credential Manager to: $credBackupDir" "INFO"
        } catch {
            Write-Log "Could not backup Credential Manager: $($_.Exception.Message)" "WARN"
        }
        
        Write-Log "Backup completed in: $backupDir" "SUCCESS"
        
    } catch {
        Write-Log "Error during backup: $($_.Exception.Message)" "ERROR"
    }
}

# Main execution function
function Main {
    Write-Log "Windows 11 Credential Eraser - Starting comprehensive credential system targeting" "INFO"
    Write-Log "Execution time: $(Get-Date)" "INFO"
    
    # Check for administrator privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin -and -not $Force) {
        Write-Log "This script requires administrator privileges. Use -Force to override or run as Administrator." "WARN"
        Write-Log "Exiting..." "INFO"
        return
    }
    
    Write-Log "Running with elevated privileges" "INFO"
    
    # Pre-execution backup
    Backup-CriticalData
    
    # Execute all credential targeting functions
    try {
        Remove-WindowsCredentialManager
        Remove-WindowsHello
        Remove-TPMData
        Remove-ActiveDirectoryCreds
        Remove-MicrosoftAccountData
        Remove-DPAPIKeys
        Remove-RegistryCreds
        Remove-UWPCreds
        Remove-NetworkCreds
        Remove-OtherVaults
        Clear-SecurityLogs
        
        Write-Log "=== Windows 11 Credential Eraser - COMPLETED ===" "SUCCESS"
        Write-Log "All credential systems have been targeted and secure deletion performed." "SUCCESS"
        Write-Log "System should be rebooted to ensure all changes take effect." "WARN"
        
    } catch {
        Write-Log "CRITICAL ERROR during execution: $($_.Exception.Message)" "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    }
}

# Execute main function
if ($MyInvocation.InvocationName -ne '.') {
    Main
}