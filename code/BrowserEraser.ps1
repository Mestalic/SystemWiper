# BrowserEraser.ps1 - Comprehensive Browser Credential Eraser
# Targets all major browsers: Edge, Chrome, Opera, Vivaldi, Brave, Firefox, Tor
# Implements DPAPI decryption, profile detection, and secure deletion
# Author: Security Research Team
# Version: 1.0

param(
    [switch]$DryRun = $false,
    [switch]$NoDelete = $false,
    [string]$LogFile = "BrowserEraser_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",
    [switch]$Force = $false,
    [switch]$IncludeSystemProfiles = $false
)

# Global variables
$Global:LogEntries = @()
$Global:TotalFilesDeleted = 0
$Global:TotalBytesDeleted = 0
$Global:Errors = @()

# Function: Write-Log
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Host $logEntry
    $Global:LogEntries += $logEntry
    
    # Also write to file
    try {
        Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore file write errors
    }
}

# Function: Test-Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function: Secure-Delete-File
function Secure-Delete-File {
    param(
        [string]$FilePath,
        [int]$Passes = 3
    )
    
    if (-not (Test-Path $FilePath)) {
        return $false
    }
    
    $fileInfo = Get-Item $FilePath
    $originalSize = $fileInfo.Length
    
    try {
        # Multiple pass overwrite for secure deletion
        for ($pass = 0; $pass -lt $Passes; $pass++) {
            $stream = [System.IO.File]::Open($FilePath, 'OpenOrCreate', 'ReadWrite', 'None')
            
            # Write random data
            $randomData = New-Object byte[] $fileInfo.Length
            $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
            $rng.GetBytes($randomData)
            $rng.Dispose()
            
            $stream.Write($randomData, 0, $randomData.Length)
            $stream.Flush()
            $stream.Close()
        }
        
        # Final pass with zeros
        $stream = [System.IO.File]::Open($FilePath, 'OpenOrCreate', 'ReadWrite', 'None')
        $zeroData = New-Object byte[] $fileInfo.Length
        $stream.Write($zeroData, 0, $zeroData.Length)
        $stream.Flush()
        $stream.Close()
        
        # Delete the file
        Remove-Item $FilePath -Force -ErrorAction Stop
        
        $Global:TotalFilesDeleted++
        $Global:TotalBytesDeleted += $originalSize
        
        Write-Log "Securely deleted: $FilePath ($originalSize bytes)" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error securely deleting $FilePath : $($_.Exception.Message)" "ERROR"
        $Global:Errors += "Failed to delete: $FilePath - $($_.Exception.Message)"
        return $false
    }
}

# Function: Remove-FileSecurely
function Remove-FileSecurely {
    param([string]$FilePath)
    
    if ($NoDelete) {
        Write-Log "[DRY-RUN] Would securely delete: $FilePath" "INFO"
        return $true
    }
    
    if ($DryRun) {
        Write-Log "[DRY-RUN] Would delete: $FilePath" "INFO"
        return $true
    }
    
    return Secure-Delete-File $FilePath
}

# Function: Decrypt-DPAPI
function Decrypt-DPAPI {
    param([byte[]]$EncryptedData)
    
    try {
        $unprotected = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $EncryptedData, 
            $null, 
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return $unprotected
    }
    catch {
        Write-Log "DPAPI decryption failed: $($_.Exception.Message)" "WARNING"
        return $null
    }
}

# Function: Get-ChromiumAESKey
function Get-ChromiumAESKey {
    param([string]$LocalStatePath)
    
    if (-not (Test-Path $LocalStatePath)) {
        return $null
    }
    
    try {
        $localState = Get-Content $LocalStatePath -Raw -ErrorAction Stop
        
        # Parse JSON to find encrypted_key
        $json = $localState | ConvertFrom-Json
        
        if (-not $json.PSObject.Properties.Name -contains "os_crypt") {
            Write-Log "No os_crypt section found in Local State" "WARNING"
            return $null
        }
        
        $encryptedKeyB64 = $json.os_crypt.encrypted_key
        if (-not $encryptedKeyB64) {
            Write-Log "No encrypted_key found in Local State" "WARNING"
            return $null
        }
        
        # Decode base64 and remove "DPAPI" prefix
        $encryptedData = [System.Convert]::FromBase64String($encryptedKeyB64)
        
        # Remove "DPAPI" prefix (first 5 bytes)
        if ($encryptedData.Length -gt 5 -and ($encryptedData[0] -eq 68 -and $encryptedData[1] -eq 80 -and $encryptedData[2] -eq 65 -and $encryptedData[3] -eq 80 -and $encryptedData[4] -eq 73)) {
            $dpapiData = $encryptedData[5..($encryptedData.Length - 1)]
        }
        else {
            Write-Log "Invalid DPAPI prefix in encrypted_key" "WARNING"
            return $null
        }
        
        # Decrypt using DPAPI
        $aesKey = Decrypt-DPAPI $dpapiData
        
        if ($aesKey -and $aesKey.Length -eq 32) {
            return $aesKey
        }
        else {
            Write-Log "Invalid AES key length or decryption failed" "WARNING"
            return $null
        }
    }
    catch {
        Write-Log "Error parsing Local State or decrypting key: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Function: Test-SQLite
function Test-SQLite {
    param([string]$FilePath)
    
    try {
        $stream = [System.IO.File]::OpenRead($FilePath)
        $buffer = New-Object byte[](16)
        $bytesRead = $stream.Read($buffer, 0, 16)
        $stream.Close()
        
        # SQLite magic header: "SQLite format 3\0"
        return ($bytesRead -eq 16 -and $buffer[0] -eq 0x53 -and $buffer[1] -eq 0x51 -and $buffer[2] -eq 0x4C -and $buffer[3] -eq 0x69)
    }
    catch {
        return $false
    }
}

# Function: Get-UserProfiles
function Get-UserProfiles {
    $profiles = @()
    
    try {
        $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Default)
        
        $profileKeys = $hive.GetSubKeyNames() | Where-Object { $_ -match '^[0-9A-F-]{36}$' -or $_ -match '^S-1-5-' }
        
        foreach ($sid in $profileKeys) {
            try {
                $key = $hive.OpenSubKey("$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
                if ($key) {
                    $appData = $key.GetValue("AppData")
                    $localAppData = $key.GetValue("Local AppData")
                    
                    if ($appData -or $localAppData) {
                        $profiles += @{
                            SID = $sid
                            AppData = $appData
                            LocalAppData = $localAppData
                        }
                    }
                    $key.Close()
                }
            }
            catch {
                # Continue with other profiles
            }
        }
    }
    catch {
        Write-Log "Error reading user profiles from registry: $($_.Exception.Message)" "ERROR"
    }
    
    return $profiles
}

# Function: Remove-ChromiumProfile
function Remove-ChromiumProfile {
    param(
        [string]$ProfilePath,
        [string]$BrowserName
    )
    
    Write-Log "Processing $BrowserName profile: $ProfilePath" "INFO"
    
    $filesToDelete = @()
    $artifactsFound = @{}
    
    # Define Chromium artifacts
    $artifacts = @{
        "Login Data" = "*.ldb"
        "Cookies" = "*.ldb"
        "Web Data" = "*.ldb"
        "Local Storage" = "leveldb"
        "Session Storage" = "Session Storage"
        "Local State" = "Local State"
    }
    
    # Handle Default profile structure
    $defaultPath = Join-Path $ProfilePath "Default"
    if (Test-Path $defaultPath) {
        Write-Log "Found Default profile directory" "INFO"
        
        # Process SQLite databases
        $sqliteFiles = Get-ChildItem -Path $defaultPath -Filter "*.ldb" -Recurse
        foreach ($file in $sqliteFiles) {
            $filesToDelete += $file.FullName
        }
        
        # Process LevelDB directories
        $leveldbDirs = @("Session Storage", "Local Storage\leveldb")
        foreach ($dirName in $leveldbDirs) {
            $dirPath = Join-Path $defaultPath $dirName
            if (Test-Path $dirPath) {
                $files = Get-ChildItem -Path $dirPath -Recurse -File
                foreach ($file in $files) {
                    $filesToDelete += $file.FullName
                }
            }
        }
        
        # Process Local State (DPAPI-encrypted key)
        $localStatePath = Join-Path $defaultPath "Local State"
        if (Test-Path $localStatePath) {
            $filesToDelete += $localStatePath.FullName
            
            # Log AES key information
            $aesKey = Get-ChromiumAESKey $localStatePath.FullName
            if ($aesKey) {
                Write-Log "$BrowserName: DPAPI-encrypted AES key found and will be removed" "INFO"
            }
            else {
                Write-Log "$BrowserName: Local State found but key decryption failed" "WARNING"
            }
        }
    }
    else {
        Write-Log "No Default profile found in $ProfilePath" "WARNING"
    }
    
    # Check for other profile directories
    $otherProfiles = Get-ChildItem -Path $ProfilePath -Directory | Where-Object { $_.Name -ne "Default" }
    foreach ($profile in $otherProfiles) {
        if (-not $IncludeSystemProfiles -and $profile.Name -match "^(Profile|Default|Default Profile|System Profile)") {
            Write-Log "Skipping system profile: $($profile.Name)" "INFO"
            continue
        }
        
        Write-Log "Found additional profile: $($profile.Name)" "INFO"
        $sqliteFiles = Get-ChildItem -Path $profile.FullName -Filter "*.ldb" -Recurse
        foreach ($file in $sqliteFiles) {
            $filesToDelete += $file.FullName
        }
        
        $localStatePath = Join-Path $profile.FullName "Local State"
        if (Test-Path $localStatePath) {
            $filesToDelete += $localStatePath.FullName
        }
    }
    
    # Delete files securely
    foreach ($filePath in $filesToDelete) {
        if (Test-Path $filePath) {
            Remove-FileSecurely $filePath
        }
    }
    
    # Remove empty directories
    $dirsToCheck = @(
        (Join-Path $ProfilePath "Default\Session Storage"),
        (Join-Path $ProfilePath "Default\Local Storage\leveldb"),
        (Join-Path $ProfilePath "Default\Local Storage"),
        (Join-Path $ProfilePath "Default")
    )
    
    foreach ($dirPath in $dirsToCheck) {
        if (Test-Path $dirPath) {
            try {
                $files = Get-ChildItem -Path $dirPath -Recurse -File
                if ($files.Count -eq 0) {
                    Remove-Item $dirPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                # Continue with other directories
            }
        }
    }
    
    Write-Log "Completed $BrowserName profile cleanup" "SUCCESS"
}

# Function: Remove-FirefoxProfile
function Remove-FirefoxProfile {
    param([string]$ProfilePath)
    
    Write-Log "Processing Firefox profile: $ProfilePath" "INFO"
    
    $filesToDelete = @()
    
    # Define Firefox credential files
    $firefoxFiles = @(
        "logins.json",
        "key4.db",
        "key3.db",
        "cookies.sqlite",
        "formhistory.sqlite",
        "places.sqlite",
        "sessionstore.jsonlz4",
        "cert9.db"
    )
    
    foreach ($fileName in $firefoxFiles) {
        $filePath = Join-Path $ProfilePath $fileName
        if (Test-Path $filePath) {
            $filesToDelete += $filePath
            Write-Log "Found Firefox file: $fileName" "INFO"
        }
    }
    
    # Handle sessionstore-backups directory
    $backupDir = Join-Path $ProfilePath "sessionstore-backups"
    if (Test-Path $backupDir) {
        $backupFiles = Get-ChildItem -Path $backupDir -File
        foreach ($file in $backupFiles) {
            $filesToDelete += $file.FullName
        }
        Write-Log "Found Firefox session backups directory" "INFO"
    }
    
    # Delete files securely
    foreach ($filePath in $filesToDelete) {
        Remove-FileSecurely $filePath
    }
    
    Write-Log "Completed Firefox profile cleanup" "SUCCESS"
}

# Function: Get-FirefoxProfiles
function Get-FirefoxProfiles {
    param([string]$AppDataPath)
    
    $profiles = @()
    $firefoxProfilesPath = Join-Path $AppDataPath "Mozilla\Firefox\Profiles"
    
    if (Test-Path $firefoxProfilesPath) {
        $profileDirs = Get-ChildItem -Path $firefoxProfilesPath -Directory
        foreach ($profileDir in $profileDirs) {
            $profiles += $profileDir.FullName
            Write-Log "Found Firefox profile: $($profileDir.Name)" "INFO"
        }
    }
    
    return $profiles
}

# Function: Get-TorBrowserProfiles
function Get-TorBrowserProfiles {
    param([string]$ProgramFilesPath)
    
    $profiles = @()
    $torPaths = @(
        (Join-Path $ProgramFilesPath "Tor Browser"),
        (Join-Path $env:LOCALAPPDATA "TorBrowser"),
        (Join-Path $env:APPDATA "TorBrowser")
    )
    
    foreach ($torPath in $torPaths) {
        if (Test-Path $torPath) {
            $browserDataPath = Join-Path $torPath "Data\Browser"
            if (Test-Path $browserDataPath) {
                $profilesDir = Join-Path $browserDataPath "Profiles"
                if (Test-Path $profilesDir) {
                    $profileDirs = Get-ChildItem -Path $profilesDir -Directory
                    foreach ($profileDir in $profileDirs) {
                        $profiles += $profileDir.FullName
                        Write-Log "Found Tor Browser profile: $($profileDir.Name)" "INFO"
                    }
                }
            }
        }
    }
    
    return $profiles
}

# Function: Process-ChromiumBrowsers
function Process-ChromiumBrowsers {
    param([hashtable]$UserProfiles)
    
    # Browser configurations
    $browsers = @(
        @{
            Name = "Microsoft Edge"
            BasePath = "Microsoft\Edge\User Data"
            SearchPaths = @()
        },
        @{
            Name = "Google Chrome"
            BasePath = "Google\Chrome\User Data"
            SearchPaths = @()
        },
        @{
            Name = "Brave"
            BasePath = "BraveSoftware\Brave-Browser\User Data"
            SearchPaths = @()
        },
        @{
            Name = "Vivaldi"
            BasePath = "Vivaldi\User Data"
            SearchPaths = @()
        },
        @{
            Name = "Opera"
            BasePath = "Opera"
            SearchPaths = @("Opera Stable", "Opera Developer")
        }
    )
    
    foreach ($browser in $browsers) {
        Write-Log "========================================" "INFO"
        Write-Log "Processing $($browser.Name)" "INFO"
        Write-Log "========================================" "INFO"
        
        foreach ($profile in $UserProfiles) {
            # Check LocalAppData
            if ($profile.LocalAppData) {
                $basePath = Join-Path $profile.LocalAppData $browser.BasePath
                if (Test-Path $basePath) {
                    Remove-ChromiumProfile $basePath $browser.Name
                }
            }
            
            # Check AppData for Opera
            if ($browser.Name -eq "Opera" -and $profile.AppData) {
                foreach ($operaPath in $browser.SearchPaths) {
                    $fullPath = Join-Path (Join-Path $profile.AppData "Opera") $operaPath
                    if (Test-Path $fullPath) {
                        Remove-ChromiumProfile $fullPath $browser.Name
                    }
                }
            }
        }
    }
}

# Function: Process-Firefox
function Process-Firefox {
    param([hashtable]$UserProfiles)
    
    Write-Log "========================================" "INFO"
    Write-Log "Processing Mozilla Firefox" "INFO"
    Write-Log "========================================" "INFO"
    
    foreach ($profile in $UserProfiles) {
        if ($profile.AppData) {
            $firefoxProfiles = Get-FirefoxProfiles $profile.AppData
            foreach ($firefoxProfile in $firefoxProfiles) {
                Remove-FirefoxProfile $firefoxProfile
            }
        }
    }
}

# Function: Process-TorBrowser
function Process-TorBrowser {
    Write-Log "========================================" "INFO"
    Write-Log "Processing Tor Browser" "INFO"
    Write-Log "========================================" "INFO"
    
    $torProfiles = Get-TorBrowserProfiles $env:PROGRAMFILES
    foreach ($torProfile in $torProfiles) {
        Remove-FirefoxProfile $torProfile
    }
}

# Function: Show-Summary
function Show-Summary {
    Write-Log "========================================" "INFO"
    Write-Log "CLEANUP SUMMARY" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "Total files deleted: $Global:TotalFilesDeleted" "INFO"
    Write-Log "Total bytes securely overwritten: $($Global:TotalBytesDeleted)" "INFO"
    Write-Log "Total size (MB): $([math]::Round($Global:TotalBytesDeleted / 1MB, 2))" "INFO"
    
    if ($Global:Errors.Count -gt 0) {
        Write-Log "Errors encountered:" "ERROR"
        foreach ($error in $Global:Errors) {
            Write-Log "  - $error" "ERROR"
        }
    }
    
    Write-Log "========================================" "INFO"
}

# Main execution
function Main {
    Write-Log "========================================" "INFO"
    Write-Log "BrowserEraser v1.0 - Starting Cleanup" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "Log file: $LogFile" "INFO"
    
    if ($DryRun) {
        Write-Log "DRY RUN MODE - No files will be deleted" "WARNING"
    }
    elseif ($NoDelete) {
        Write-Log "NO DELETE MODE - No deletion will occur" "WARNING"
    }
    else {
        Write-Log "DELETION MODE - Files will be securely deleted" "INFO"
    }
    
    # Check for administrator privileges (recommended for secure deletion)
    if (-not (Test-Administrator)) {
        Write-Log "Not running as administrator. Secure deletion may be limited." "WARNING"
        if (-not $Force) {
            Write-Log "Use -Force to continue without admin privileges" "WARNING"
            return
        }
    }
    
    # Get user profiles
    Write-Log "========================================" "INFO"
    Write-Log "Detecting User Profiles" "INFO"
    Write-Log "========================================" "INFO"
    
    $userProfiles = Get-UserProfiles
    Write-Log "Found $($userProfiles.Count) user profiles" "INFO"
    
    # Process each browser family
    Process-ChromiumBrowsers $userProfiles
    Process-Firefox $userProfiles
    Process-TorBrowser
    
    # Show summary
    Show-Summary
}

# Execute main function
try {
    Main
}
catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}
