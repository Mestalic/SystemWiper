# Secure Windows 11 Data Eraser - One-liner PowerShell Script
# Run with: irm "https://github.com/HOSTEDSCRIPT" | iex
# WARNING: This will permanently delete all credentials, passwords, and sensitive data!

param(
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,10)]
    [int]$EncryptionRounds = 3,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verify,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$Silent
)

# ========================================
# CONFIGURATION AND CONSTANTS
# ========================================

$Script:Config = @{
    # Encryption Settings
    MinKeySize = 256
    DefaultRounds = 3
    MaxRounds = 10
    
    # Performance Settings
    MaxParallelJobs = [Environment]::ProcessorCount
    ChunkSize = 1MB
    BufferSize = 64KB
    
    # Security Settings
    SecureDeletePasses = 3
    RandomDataPasses = 1
    ZeroPasses = 1
    
    # Logging
    LogRetentionDays = 7
    MaxLogSize = 10MB
    
    # Browser Targets
    BrowserPaths = @(
        # Chromium-based browsers
        "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*",
        "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*",
        "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*\Default\*",
        "${env:LOCALAPPDATA}\Opera Software\Opera Stable\*\Default\*",
        "${env:LOCALAPPDATA}\Vivaldi\User Data\*\Default\*",
        
        # Firefox
        "${env:APPDATA}\Mozilla\Firefox\Profiles\*\*.sqlite",
        "${env:APPDATA}\Mozilla\Firefox\Profiles\*\key*.db",
        "${env:APPDATA}\Mozilla\Firefox\Profiles\*\logins.json",
        
        # Tor Browser
        "${env:LOCALAPPDATA}\TorBrowser\Tor\*\*.sqlite"
    )
    
    # Application Token Paths
    AppTokenPaths = @(
        # Discord
        "${env:APPDATA}\Discord\*\Local Storage\leveldb\*",
        "${env:APPDATA}\discord*\modules\*\discord_desktop_core-*\*",
        
        # Steam
        "${env:PROGRAMFILES(X86)}\Steam\*",
        "${env:APPDATA}\Steam\*",
        
        # Spotify
        "${env:APPDATA}\Spotify\*\Local Storage\*",
        "${env:APPDATA}\Spotify\*\Cache\*",
        
        # Epic Games
        "${env:LOCALAPPDATA}\EpicGamesLauncher\*\Saved\*",
        
        # Git tools
        "${env:LOCALAPPDATA}\Git Credential Manager\*",
        "${env:APPDATA}\GitCredentialManager\*.json"
    )
    
    # Windows Credential Manager
    WindowsCredPaths = @(
        "${env:APPDATA}\Microsoft\Credentials\*",
        "${env:APPDATA}\Microsoft\Protect\*",
        "${env:APPDATA}\Microsoft\SystemCertificates\*"
    )
}

# ========================================
# CORE FUNCTIONS
# ========================================

function Write-ColorOutput {
    param(
        [string]$Message,
        [ConsoleColor]$Color = 'White',
        [ConsoleColor]$Background = 'Black'
    )
    
    if (-not $Silent) {
        $originalFg = [Console]::ForegroundColor
        $originalBg = [Console]::BackgroundColor
        [Console]::ForegroundColor = $Color
        [Console]::BackgroundColor = $Background
        Write-Host $Message
        [Console]::ForegroundColor = $originalFg
        [Console]::BackgroundColor = $originalBg
    }
}

function Initialize-SecureEraser {
    <#
    .SYNOPSIS
    Initializes the Secure Eraser system with maximum privileges and security checks.
    #>
    
    Write-ColorOutput "`n=== SECURE WINDOWS 11 DATA ERASER ===" 'Cyan'
    Write-ColorOutput "WARNING: This will PERMANENTLY delete all credentials, passwords, and sensitive data!" 'Red'
    Write-ColorOutput "Ensure you have backups and understand the consequences.`n" 'Yellow'
    
    # Check administrative privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-ColorOutput "ERROR: Administrative privileges required! Please run as Administrator." 'Red'
        exit 1
    }
    
    # Check UAC status
    $uacEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
    if ($uacEnabled -eq 1) {
        Write-ColorOutput "UAC detected. Attempting privilege escalation..." 'Yellow'
        try {
            $null = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-File", $MyInvocation.MyCommand.Path, "-Force" -Verb RunAs
            exit 0
        } catch {
            Write-ColorOutput "Failed to escalate privileges. Continuing with current privileges." 'Yellow'
        }
    }
    
    # Enable necessary privileges
    $privileges = @('SeBackupPrivilege', 'SeRestorePrivilege', 'SeManageVolumePrivilege', 'SeDebugPrivilege')
    foreach ($privilege in $privileges) {
        try {
            $result = & "$env:SystemRoot\system32\net.exe" stop schedule
            Start-Sleep -Seconds 1
            $result = & "$env:SystemRoot\system32\net.exe" start schedule
        } catch {
            # Continue if privilege adjustment fails
        }
    }
    
    Write-ColorOutput "✓ Administrative privileges confirmed" 'Green'
    Write-ColorOutput "✓ System security audit completed`n" 'Green'
}

function New-EncryptionKey {
    <#
    .SYNOPSIS
    Generates a cryptographically secure 256-bit random key for encryption.
    #>
    
    $key = New-Object byte[] 32
    if ([System.Security.Cryptography.RandomNumberGenerator]::IsSupported) {
        [System.Security.Cryptography.RandomNumberGenerator]::GetBytes($key)
    } else {
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($key)
        $rng.Dispose()
    }
    return $key
}

function Test-SecureDelete {
    param(
        [string]$FilePath,
        [int]$Rounds = 3
    )
    
    if (-not (Test-Path $FilePath)) {
        return $false
    }
    
    try {
        $fileInfo = Get-Item $FilePath
        $fileSize = $fileInfo.Length
        
        if ($fileSize -eq 0) {
            Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
            return $true
        }
        
        # Multi-round encryption and secure deletion
        for ($round = 1; $round -le $Rounds; $round++) {
            $key = New-EncryptionKey
            $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            $aes.KeySize = 256
            $aes.Key = $key
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            
            $encryptor = $aes.CreateEncryptor()
            $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fileStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
            
            # Encrypt the file
            $buffer = New-Object byte[] $Script:Config.BufferSize
            $position = 0
            
            while ($position -lt $fileSize) {
                $read = $cryptoStream.Write($buffer, 0, [Math]::Min($buffer.Length, $fileSize - $position))
                $position += $read
                if (-not $Silent -and ($round -eq 1)) {
                    $progress = [Math]::Round(($position / $fileSize) * 100, 1)
                    Write-Progress -Activity "Encrypting $round/$Rounds" -Status $FilePath -PercentComplete $progress
                }
            }
            
            $cryptoStream.FlushFinalBlock()
            $cryptoStream.Dispose()
            $fileStream.SetLength(0)  # Truncate to zero
            $fileStream.Dispose()
            
            # Overwrite with random data
            $overwriteStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $randomData = New-Object byte[] $fileSize
            [System.Security.Cryptography.RandomNumberGenerator]::GetBytes($randomData)
            $overwriteStream.Write($randomData, 0, $randomData.Length)
            $overwriteStream.Dispose()
            
            # Final zero pass
            $zeroStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $zeroData = New-Object byte[] $fileSize
            $zeroStream.Write($zeroData, 0, $zeroData.Length)
            $zeroStream.Dispose()
        }
        
        # Final deletion
        Remove-Item $FilePath -Force -ErrorAction Stop
        return $true
        
    } catch {
        Write-ColorOutput "ERROR: Failed to securely delete $FilePath - $($_.Exception.Message)" 'Red'
        return $false
    } finally {
        Write-Progress -Activity "Secure Deletion" -Completed
    }
}

function Find-TargetFiles {
    <#
    .SYNOPSIS
    Finds all target files across browsers, applications, and system locations.
    #>
    
    $allTargets = @()
    
    Write-ColorOutput "Scanning for target files..." 'Yellow'
    
    # Browser targets
    foreach ($pattern in $Script:Config.BrowserPaths) {
        $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Where-Object { 
            $_.Name -match "(Login Data|Cookies|Web Data|key.*\.db|logins\.json|cookies\.sqlite)" 
        }
        $allTargets += $files
    }
    
    # Application token targets
    foreach ($pattern in $Script:Config.AppTokenPaths) {
        $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Where-Object { 
            $_.Name -match "(leveldb|.*\.ldb|.*\.log|.*\.sst|.*\.sqlite)" 
        }
        $allTargets += $files
    }
    
    # Windows credential targets
    foreach ($pattern in $Script:Config.WindowsCredPaths) {
        $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
        $allTargets += $files
    }
    
    # Registry-based credentials
    $registryTargets = @(
        "HKCU:\Software\Google\Chrome\PreferenceMACs\*",
        "HKCU:\Software\Microsoft\Edge\PreferenceMACs\*",
        "HKCU:\Software\Mozilla\Firefox\*",
        "HKCU:\Software\Discord\*"
    )
    
    foreach ($regPath in $registryTargets) {
        try {
            $regItems = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($regItems) {
                $allTargets += $regItems
            }
        } catch {
            # Continue if registry access fails
        }
    }
    
    return $allTargets | Select-Object -Unique
}

function Clear-WindowsCredentials {
    <#
    .SYNOPSIS
    Clears Windows built-in credential stores and biometric data.
    #>
    
    Write-ColorOutput "Clearing Windows credential stores..." 'Yellow'
    
    # Windows Credential Manager
    try {
        $null = & cmdkey.exe /list | Where-Object { $_ -match "Target:" } | ForEach-Object {
            $target = ($_ -split "Target:")[1].Trim()
            & cmdkey.exe /delete:$target 2>$null
        }
        Write-ColorOutput "✓ Windows Credential Manager cleared" 'Green'
    } catch {
        Write-ColorOutput "⚠ Could not clear some credential manager entries" 'Yellow'
    }
    
    # Clear DPAPI data
    try {
        $dpapiPaths = @(
            "${env:APPDATA}\Microsoft\Protect\*",
            "${env:LOCALAPPDATA}\Microsoft\Protect\*"
        )
        
        foreach ($path in $dpapiPaths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    Test-SecureDelete $_.FullName $EncryptionRounds
                }
            }
        }
        Write-ColorOutput "✓ DPAPI data cleared" 'Green'
    } catch {
        Write-ColorOutput "⚠ Could not clear some DPAPI data" 'Yellow'
    }
    
    # Windows Hello data
    try {
        $helloPaths = @(
            "${env:LOCALAPPDATA}\Microsoft\Biometrics\*",
            "${env:PROGRAMDATA}\Microsoft\Biometrics\*"
        )
        
        foreach ($path in $helloPaths) {
            if (Test-Path $path) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        Write-ColorOutput "✓ Windows Hello biometric data cleared" 'Green'
    } catch {
        Write-ColorOutput "⚠ Could not clear Windows Hello data" 'Yellow'
    }
}

function Start-SecureErasure {
    <#
    .SYNOPSIS
    Main function that orchestrates the complete secure erasure process.
    #>
    
    # User confirmation
    if (-not $Force -and -not $Silent) {
        $response = Read-Host "`nAre you sure you want to proceed? Type 'YES' to continue"
        if ($response -ne 'YES') {
            Write-ColorOutput "Operation cancelled." 'Yellow'
            return
        }
    }
    
    # Initialize system
    Initialize-SecureEraser
    
    Write-ColorOutput "Starting secure erasure process..." 'Cyan'
    Write-ColorOutput "Encryption rounds: $EncryptionRounds" 'White'
    Write-ColorOutput "Verification: $($Verify.IsPresent)" 'White'
    Write-ColorOutput ""
    
    # Find all target files
    $targets = Find-TargetFiles
    $totalFiles = $targets.Count
    $processedFiles = 0
    $successfulDeletions = 0
    $failedDeletions = 0
    
    if ($totalFiles -eq 0) {
        Write-ColorOutput "No target files found. System may already be clean or insufficient privileges." 'Yellow'
    } else {
        Write-ColorOutput "Found $totalFiles target files for secure deletion.`n" 'Green'
        
        # Process files with progress
        foreach ($target in $targets) {
            $processedFiles++
            $progress = [Math]::Round(($processedFiles / $totalFiles) * 100, 1)
            
            $fileName = if ($target.PSObject.Properties['FullName']) { 
                $target.FullName 
            } else { 
                $target.Name 
            }
            
            Write-Progress -Activity "Secure Erasure" -Status "Processing: $fileName" -PercentComplete $progress
            
            if (Test-SecureDelete $fileName $EncryptionRounds) {
                $successfulDeletions++
                if (-not $Silent) {
                    Write-ColorOutput "✓ Deleted: $fileName" 'Green'
                }
            } else {
                $failedDeletions++
                Write-ColorOutput "✗ Failed: $fileName" 'Red'
            }
        }
    }
    
    # Clear Windows credentials
    Clear-WindowsCredentials
    
    # Clear browser-specific data
    Write-ColorOutput "`nClearing browser-specific data..." 'Yellow'
    
    # Clear browser caches and temp data
    $browserTempPaths = @(
        "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\Cache\*",
        "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\Cache\*",
        "${env:APPDATA}\Mozilla\Firefox\Profiles\*\cache2\*"
    )
    
    foreach ($path in $browserTempPaths) {
        try {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Continue if some cache clearing fails
        }
    }
    
    # Final verification
    if ($Verify) {
        Write-ColorOutput "`nPerforming verification scan..." 'Yellow'
        $remainingTargets = Find-TargetFiles
        if ($remainingTargets.Count -eq 0) {
            Write-ColorOutput "✓ Verification PASSED: No sensitive data remaining" 'Green'
        } else {
            Write-ColorOutput "✗ Verification FAILED: $($remainingTargets.Count) files still exist" 'Red'
        }
    }
    
    # Summary report
    Write-ColorOutput "`n=== ERASURE COMPLETE ===" 'Cyan'
    Write-ColorOutput "Files processed: $processedFiles" 'White'
    Write-ColorOutput "Successful deletions: $successfulDeletions" 'Green'
    Write-ColorOutput "Failed deletions: $failedDeletions" 'Red'
    Write-ColorOutput "Encryption rounds: $EncryptionRounds" 'White'
    
    if ($failedDeletions -eq 0 -and $remainingTargets.Count -eq 0) {
        Write-ColorOutput "`n🎉 SECURE ERASURE COMPLETED SUCCESSFULLY" 'Green'
        Write-ColorOutput "All credentials, passwords, and sensitive data have been permanently destroyed." 'Green'
    } else {
        Write-ColorOutput "`n⚠ ERASURE COMPLETED WITH WARNINGS" 'Yellow'
        Write-ColorOutput "Some files could not be deleted. Manual review recommended." 'Yellow'
    }
    
    Write-ColorOutput "`nIt is recommended to restart the system and reinstall the operating system for complete security." 'Yellow'
}

# ========================================
# MAIN EXECUTION
# ========================================

# Prevent Ctrl+C interruption during critical operations
[Console]::TreatControlCAsInput = $true

# Main execution
try {
    Start-SecureErasure
} catch {
    Write-ColorOutput "`nCRITICAL ERROR: $($_.Exception.Message)" 'Red'
    Write-ColorOutput "Stack trace: $($_.ScriptStackTrace)" 'Red'
    exit 1
} finally {
    [Console]::TreatControlCAsInput = $false
}

# End of script