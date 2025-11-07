# COMPREHENSIVE WINDOWS DATA CLEANER
# Professional file deletion with proper browser targeting
# Execute with: irm "https://raw.githubusercontent.com/Mestalic/SystemWiper/main/Invoke-UltimateSecureEraser.ps1" | iex

param(
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$Deep
)

# ========================================
# CONFIGURATION
# ========================================

$Global:Config = @{
    # Protected system processes
    ProtectedProcesses = @(
        "wininit", "winlogon", "csrss", "smss", "lsass", "svchost", "dwm", "fontdrvhost",
        "system", "registry", "services", "audiodg", "taskhostw", "runtimebroker", "conhost", "explorer"
    )
    
    # Browser databases to target
    BrowserDatabases = @{
        Chrome = @{
            Paths = @(
                "${env:LOCALAPPDATA}\Google\Chrome\User Data\*",
                "${env:LOCALAPPDATA}\Google\Chrome\User Data\*\Default"
            )
            Files = @(
                "*.sqlite", "*.ldb", "*.log", "*.sst", "*.Cookie", "Login Data*", "Web Data*",
                "Current Session", "Current Tabs", "Last Session", "Last Tabs", "Bookmarks",
                "Preferences", "Local Storage*", "Session Storage*", "Extensions\*", "Sync Data\*"
            )
        }
        Edge = @{
            Paths = @(
                "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*",
                "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\*\Default"
            )
            Files = @(
                "*.sqlite", "*.ldb", "*.log", "*.Cookie", "Login Data*", "Web Data*",
                "Current Session", "Current Tabs", "Last Session", "Last Tabs", "Bookmarks",
                "Preferences", "Local Storage*", "Session Storage*"
            )
        }
        Firefox = @{
            Paths = @(
                "${env:APPDATA}\Mozilla\Firefox\Profiles\*"
            )
            Files = @(
                "*.sqlite", "*.log", "formhistory.sqlite", "cookies.sqlite", "places.sqlite",
                "permissions.sqlite", "addonDatabase.sqlite", "addonStartup.json"
            )
        }
        Brave = @{
            Paths = @(
                "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*",
                "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\*\Default"
            )
            Files = @(
                "*.sqlite", "*.ldb", "*.log", "*.Cookie", "Login Data*", "Web Data*",
                "Current Session", "Current Tabs", "Last Session", "Last Tabs"
            )
        }
    }
    
    # Communication apps
    CommunicationApps = @{
        Discord = @{
            Paths = @("${env:APPDATA}\Discord\*")
            Files = @("*.json", "*.log", "*.ldb", "Local Storage\*", "session_storage\*", "config\settings.json")
        }
        Teams = @{
            Paths = @("${env:LOCALAPPDATA}\Microsoft\Teams\*")
            Files = @("settings.json", "Storage\*", "logs\*", "Local Storage\*")
        }
        Slack = @{
            Paths = @("${env:APPDATA}\Slack\*")
            Files = @("*.db", "Local Storage\*", "session_storage\*", "*.json")
        }
        Zoom = @{
            Paths = @("${env:APPDATA}\Zoom\*")
            Files = @("Cache\*", "config\*", "s3:\*", "web*\Cache\*")
        }
    }
    
    # Office and documents
    OfficeApps = @{
        RecentFiles = @(
            "${env:APPDATA}\Microsoft\Windows\Recent\*",
            "${env:LOCALAPPDATA}\Microsoft\Windows\Recent\*"
        )
        Documents = @(
            "${env:USERPROFILE}\Documents\*",
            "${env:USERPROFILE}\Desktop\*"
        )
        Downloads = @(
            "${env:USERPROFILE}\Downloads\*"
        )
    }
}

# ========================================
# CORE FUNCTIONS
# ========================================

function Write-Status {
    param($Message, $Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Get-TakeOwnership {
    <# Takes ownership of a file or folder #>
    param([string]$Path)
    
    try {
        $acl = Get-Acl $Path
        $acl.SetAccessRuleProtection($false, $false)
        
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser.Groups[0], "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl $Path $acl
        return $true
    } catch {
        return $false
    }
}

function Remove-SafeFile {
    <# Enhanced file removal with ownership and multiple methods #>
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        return $false
    }
    
    try {
        $fileInfo = Get-Item $FilePath -Force
        $fileSize = $fileInfo.Length
        
        # Skip empty files
        if ($fileSize -eq 0) {
            Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
            return $true
        }
        
        # Method 1: Direct delete
        try {
            Remove-Item $FilePath -Force -ErrorAction Stop
            return $true
        } catch {
            # Method 2: Take ownership and delete
            $ownershipResult = Get-TakeOwnership $FilePath
            if ($ownershipResult) {
                try {
                    Remove-Item $FilePath -Force -ErrorAction Stop
                    return $true
                } catch {
                    # Method 3: Simple overwrite
                    $stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open)
                    $bytes = [System.Text.Encoding]::ASCII.GetBytes("DELETED")
                    $stream.Write($bytes, 0, $bytes.Length)
                    $stream.SetLength($bytes.Length)
                    $stream.Close()
                    Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
                    return $true
                }
            }
        }
        
        return $false
        
    } catch {
        Write-Status "  ✗ Failed: $FilePath" "Red"
        return $false
    }
}

function Find-BrowserFiles {
    <# Comprehensive browser file search #>
    Write-Status "Scanning browsers for data files..." "Yellow"
    
    $foundFiles = @()
    $browserConfig = $Global:Config.BrowserDatabases
    
    foreach ($browserName in $browserConfig.Keys) {
        $browser = $browserConfig[$browserName]
        Write-Status "  Checking $browserName..." "Cyan"
        
        foreach ($path in $browser.Paths) {
            foreach ($filePattern in $browser.Files) {
                try {
                    $fullPattern = Join-Path $path $filePattern
                    $files = Get-ChildItem -Path $fullPattern -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 }
                    $foundFiles += $files
                } catch {
                    # Pattern might not exist
                }
            }
        }
    }
    
    return $foundFiles
}

function Find-CommunicationFiles {
    <# Find communication app data #>
    Write-Status "Scanning communication apps..." "Yellow"
    
    $foundFiles = @()
    $commConfig = $Global:Config.CommunicationApps
    
    foreach ($appName in $commConfig.Keys) {
        $app = $commConfig[$appName]
        Write-Status "  Checking $appName..." "Cyan"
        
        foreach ($path in $app.Paths) {
            foreach ($filePattern in $app.Files) {
                try {
                    $fullPattern = Join-Path $path $filePattern
                    $files = Get-ChildItem -Path $fullPattern -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 }
                    $foundFiles += $files
                } catch {
                    # Pattern might not exist
                }
            }
        }
    }
    
    return $foundFiles
}

function Find-RecentFiles {
    <# Find recent documents and files #>
    Write-Status "Scanning recent files..." "Yellow"
    
    $foundFiles = @()
    $officeConfig = $Global:Config.OfficeApps
    
    # Recent files
    foreach ($path in $officeConfig.RecentFiles) {
        try {
            $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
            $foundFiles += $files
        } catch {}
    }
    
    # Documents
    foreach ($path in $officeConfig.Documents) {
        try {
            $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
            $foundFiles += $files
        } catch {}
    }
    
    # Downloads
    foreach ($path in $officeConfig.Downloads) {
        try {
            $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) }
            $foundFiles += $files
        } catch {}
    }
    
    return $foundFiles
}

function Kill-AppProcesses {
    <# Close apps that might lock files #>
    Write-Status "Closing applications that may lock files..." "Yellow"
    
    $processes = @(
        "chrome", "msedge", "firefox", "brave", "opera", "vivaldi",
        "discord", "teams", "slack", "zoom", "skype",
        "steam", "epicgameslauncher", "battlenet", "origin",
        "winword", "excel", "powerpoint", "outlook", "onenote"
    )
    
    foreach ($process in $processes) {
        try {
            Get-Process -Name $process -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        } catch {}
    }
    
    Start-Sleep -Seconds 3
    Write-Status "✓ Applications closed" "Green"
}

function Clear-SystemTracking {
    <# Clear system tracking data #>
    Write-Status "Clearing system tracking data..." "Yellow"
    
    # Clear recent files
    try {
        Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Recurse -Force -ErrorAction SilentlyContinue
    } catch {}
    
    # Clear temp files
    try {
        Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:LOCALAPPDATA\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    } catch {}
    
    # Clear registry recent docs
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        Remove-ItemProperty -Path $regPath -Name "RecentDocs" -ErrorAction SilentlyContinue
    } catch {}
    
    Write-Status "✓ System tracking cleared" "Green"
}

function Wipe-Memory {
    <# Clean memory usage #>
    Write-Status "Cleaning memory..." "Yellow"
    
    for ($i = 1; $i -le 3; $i++) {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        Start-Sleep -Seconds 1
    }
    
    Write-Status "✓ Memory cleaned" "Green"
}

# ========================================
# MAIN EXECUTION
# ========================================

function Start-DataCleaning {
    Write-Status "`n========================================" "White"
    Write-Status "WINDOWS DATA CLEANER" "White"
    Write-Status "========================================" "White"
    Write-Status "This will delete browser data, recent files, and sensitive information" "Red"
    
    if (-not $Force) {
        Write-Status "Type YES to continue or NO to cancel" "Red"
        $response = Read-Host "Confirm"
        if ($response -ne "YES") {
            Write-Status "Operation cancelled." "Yellow"
            return
        }
    }
    
    Write-Status "`nStarting data cleaning process..." "Cyan"
    
    # Close applications
    Kill-AppProcesses
    
    # Collect all files to delete
    $allFiles = @()
    $allFiles += Find-BrowserFiles
    $allFiles += Find-CommunicationFiles
    $allFiles += Find-RecentFiles
    
    $totalFiles = $allFiles.Count
    
    if ($totalFiles -eq 0) {
        Write-Status "No target files found. System may already be clean." "Yellow"
    } else {
        Write-Status "Found $totalFiles files to process`n" "Green"
        
        $successCount = 0
        $failedCount = 0
        
        # Process files
        foreach ($file in $allFiles) {
            $fileName = $file.Name
            if ($fileName.Length -gt 50) {
                $fileName = $fileName.Substring(0, 47) + "..."
            }
            
            Write-Status "Deleting: $fileName" "White"
            
            if (Remove-SafeFile $file.FullName) {
                $successCount++
                Write-Status "  ✓ Deleted" "Green"
            } else {
                $failedCount++
            }
        }
        
        Write-Status "`nResults:" "White"
        Write-Status "✓ Successfully deleted: $successCount files" "Green"
        if ($failedCount -gt 0) {
            Write-Status "✗ Failed to delete: $failedCount files" "Red"
        }
    }
    
    # Clear system tracking
    Clear-SystemTracking
    
    # Clean memory
    Wipe-Memory
    
    Write-Status "`n========================================" "White"
    Write-Status "DATA CLEANING COMPLETE" "Green"
    Write-Status "Browser data, recent files, and sensitive information have been deleted" "Green"
    Write-Status "========================================" "White"
}

# Start execution
try {
    Start-DataCleaning
} catch {
    Write-Status "`nERROR: $($_.Exception.Message)" "Red"
    Write-Status "Data cleaning may be incomplete" "Yellow"
}