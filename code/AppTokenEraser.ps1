# AppTokenEraser.ps1
# Comprehensive Application Token and Credential Eraser
# Targets Steam, Spotify, Epic Games, Discord, Battle.net, Origin, uPlay, Adobe CC, Office 365, GitHub/GitLab, VS Code, and more
# Uses evidence-backed file paths and registry keys from security research

param(
    [switch]$DryRun,
    [switch]$Verbose,
    [switch]$IncludeBrowserData,
    [switch]$SecureWipe,
    [int]$WipePasses = 1
)

#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# Global variables
$Global:LogFile = "$env:TEMP\AppTokenEraser_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$Global:FoundTokens = @()
$Global:ErasedItems = @()
$Global:FailedItems = @()

# Initialize logging
function Initialize-Logging {
    param()
    
    $logHeader = @"
========================================
AppTokenEraser - Token Erasure Tool
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
User: $env:USERNAME
Computer: $env:COMPUTERNAME
DryRun: $DryRun
Verbose: $Verbose
SecureWipe: $SecureWipe
WipePasses: $WipePasses
========================================
"@
    
    Add-Content -Path $Global:LogFile -Value $logHeader
    Write-Host $logHeader
}

# Enhanced logging function
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Add-Content -Path $Global:LogFile -Value $logEntry
    
    switch ($Level) {
        'INFO'    { Write-Host $logEntry -ForegroundColor Cyan }
        'WARNING' { Write-Host $logEntry -ForegroundColor Yellow }
        'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
        'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
    }
}

# Token pattern definitions for various authentication methods
$TokenPatterns = @{
    'JWT' = @(
        '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    )
    'OAuth' = @(
        'access_token=([^&\s]+)',
        'refresh_token=([^&\s]+)',
        'auth_token=([^&\s]+)',
        'token=([^&\s]{20,})'
    )
    'Base64' = @(
        '[A-Za-z0-9+/]{40,}={0,2}',
        '[A-Fa-f0-9]{40,}'
    )
    'Hex' = @(
        '[A-Fa-f0-9]{32,}',
        '0x[A-Fa-f0-9]+'
    )
    'Session' = @(
        'session[_-]?token[A-Fa-f0-9]{20,}',
        'auth[_-]?session[A-Za-z0-9]{20,}',
        'user[_-]?session[A-Za-z0-9]{20,}'
    )
    'PAT' = @(
        'ghp_[A-Za-z0-9]{36}',
        'github_pat_[A-Za-z0-9_]{82}',
        'glpat-[A-Za-z0-9_-]{20,}',
        'xoxb-[0-9]+-[0-9]+-[A-Za-z0-9-]+',
        'xoxp-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9-]+'
    )
}

# Function to test if a path is accessible
function Test-PathSafe {
    param([string]$Path)
    
    try {
        if (Test-Path $Path) {
            return $true
        }
    }
    catch {
        Write-Log "Path access denied: $Path" 'WARNING'
        return $false
    }
    return $false
}

# Function to search for tokens in file content
function Find-TokensInContent {
    param(
        [string]$Content,
        [string]$Source,
        [hashtable]$Patterns = $TokenPatterns
    )
    
    $foundTokens = @()
    
    foreach ($tokenType in $Patterns.Keys) {
        foreach ($pattern in $Patterns[$tokenType]) {
            $matches = [regex]::Matches($Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($match in $matches) {
                $token = $match.Value
                if ($token.Length -gt 20 -and $token.Length -lt 500) {
                    $foundTokens += @{
                        Type = $tokenType
                        Token = $token
                        Source = $Source
                        Line = $match.Index
                    }
                }
            }
        }
    }
    
    return $foundTokens
}

# Function to secure wipe file content (NIST 800-88 aligned)
function Secure-WipeFile {
    param(
        [string]$FilePath,
        [int]$Passes = 1
    )
    
    try {
        if (-not (Test-Path $FilePath)) {
            return $false
        }
        
        $fileInfo = Get-Item $FilePath
        $fileSize = $fileInfo.Length
        
        if ($fileSize -eq 0) {
            Remove-Item $FilePath -Force
            return $true
        }
        
        for ($pass = 1; $pass -le $Passes; $pass++) {
            $stream = [System.IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
            try {
                $buffer = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes($fileSize)
                $stream.Write($buffer, 0, $buffer.Length)
                $stream.Flush()
            }
            finally {
                $stream.Close()
            }
        }
        
        Remove-Item $FilePath -Force
        return $true
    }
    catch {
        Write-Log "Failed to securely wipe file $FilePath : $_" 'ERROR'
        return $false
    }
}

# Function to remove registry value securely
function Remove-RegistryValue {
    param(
        [string]$Hive,
        [string]$KeyPath,
        [string]$ValueName
    )
    
    try {
        $regPath = "$Hive\$KeyPath"
        if (-not (Test-Path "Registry::$regPath")) {
            return $false
        }
        
        Remove-ItemProperty -Path "Registry::$regPath" -Name $ValueName -Force -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        Write-Log "Failed to remove registry value $Hive\$KeyPath\$ValueName : $_" 'ERROR'
        return $false
    }
}

# Function to search LevelDB databases for tokens (Discord, etc.)
function Search-LevelDBForTokens {
    param([string]$DBPath)
    
    if (-not (Test-PathSafe $DBPath)) {
        return @()
    }
    
    $foundTokens = @()
    $leveldbFiles = Get-ChildItem $DBPath -Filter "*.log" -ErrorAction SilentlyContinue
    
    foreach ($file in $leveldbFiles) {
        try {
            $content = [System.IO.File]::ReadAllBytes($file.FullName)
            $textContent = [System.Text.Encoding]::UTF8.GetString($content)
            
            $tokens = Find-TokensInContent $textContent $file.FullName
            foreach ($token in $tokens) {
                $foundTokens += $token
            }
        }
        catch {
            Write-Log "Failed to read LevelDB file $($file.FullName): $_" 'WARNING'
        }
    }
    
    return $foundTokens
}

# Steam Token Erasure
function Remove-SteamTokens {
    Write-Log "=== Steam Token Erasure ===" 'INFO'
    
    $steamPaths = @(
        "$env:PROGRAMFILES (x86)\Steam",
        "$env:LOCALAPPDATA\Steam",
        "$env:APPDATA\Steam"
    )
    
    foreach ($basePath in $steamPaths) {
        if (-not (Test-PathSafe $basePath)) { continue }
        
        $configPaths = @(
            "$basePath\config\config.vdf",
            "$basePath\config\loginusers.vdf",
            "$basePath\config\steamservice.vdf"
        )
        
        foreach ($configFile in $configPaths) {
            if (Test-PathSafe $configFile) {
                try {
                    $content = Get-Content $configFile -Raw
                    $tokens = Find-TokensInContent $content $configFile
                    
                    if ($tokens.Count -gt 0) {
                        Write-Log "Found $($tokens.Count) potential tokens in $configFile" 'WARNING'
                        $Global:FoundTokens += $tokens
                        
                        if (-not $DryRun) {
                            if ($SecureWipe) {
                                if (Secure-WipeFile $configFile $WipePasses) {
                                    Write-Log "Securely wiped $configFile" 'SUCCESS'
                                    $Global:ErasedItems += $configFile
                                }
                            } else {
                                Remove-Item $configFile -Force
                                Write-Log "Removed $configFile" 'SUCCESS'
                                $Global:ErasedItems += $configFile
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to process Steam config $configFile : $_" 'ERROR'
                    $Global:FailedItems += $configFile
                }
            }
        }
    }
    
    # Steam registry keys
    $steamRegKeys = @(
        @{ Hive = 'HKEY_LOCAL_MACHINE'; Path = 'SOFTWARE\WOW6432Node\Valve\Steam' },
        @{ Hive = 'HKEY_CURRENT_USER'; Path = 'SOFTWARE\Valve\Steam' }
    )
    
    foreach ($regKey in $steamRegKeys) {
        try {
            $regPath = "$($regKey.Hive)\$($regKey.Path)"
            if (Test-Path "Registry::$regPath") {
                $properties = Get-ItemProperty "Registry::$regPath" -ErrorAction SilentlyContinue
                foreach ($property in $properties.PSObject.Properties.Name) {
                    if ($property -like "*token*" -or $property -like "*auth*" -or $property -like "*session*") {
                        Write-Log "Found Steam registry property: $property" 'WARNING'
                        if (-not $DryRun) {
                            Remove-RegistryValue $regKey.Hive $regKey.Path $property
                            Write-Log "Removed Steam registry value: $property" 'SUCCESS'
                            $Global:ErasedItems += "$regPath\$property"
                        }
                    }
                }
            }
        }
        catch {
            Write-Log "Failed to process Steam registry key $($regKey.Path) : $_" 'ERROR'
        }
    }
}

# Spotify Token Erasure
function Remove-SpotifyTokens {
    Write-Log "=== Spotify Token Erasure ===" 'INFO'
    
    $spotifyPaths = @(
        "$env:LOCALAPPDATA\Spotify",
        "$env:APPDATA\Spotify",
        "$env:LOCALAPPDATA\SpotifyBrowser"
    )
    
    foreach ($basePath in $spotifyPaths) {
        if (-not (Test-PathSafe $basePath)) { continue }
        
        $tokenFiles = @(
            "$basePath\storage\spotify_cache.db",
            "$basePath\storage\web_cache.db",
            "$basePath\data\*.db",
            "$basePath\Local Storage\*.ldb",
            "$basePath\Session Storage\*.ldb"
        )
        
        foreach ($pattern in $tokenFiles) {
            $files = Get-ChildItem $pattern -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                try {
                    $content = [System.IO.File]::ReadAllBytes($file.FullName)
                    $textContent = [System.Text.Encoding]::UTF8.GetString($content)
                    $tokens = Find-TokensInContent $textContent $file.FullName
                    
                    if ($tokens.Count -gt 0) {
                        Write-Log "Found $($tokens.Count) tokens in Spotify file: $($file.FullName)" 'WARNING'
                        $Global:FoundTokens += $tokens
                        
                        if (-not $DryRun) {
                            if ($SecureWipe) {
                                if (Secure-WipeFile $file.FullName $WipePasses) {
                                    Write-Log "Securely wiped $($file.FullName)" 'SUCCESS'
                                    $Global:ErasedItems += $file.FullName
                                }
                            } else {
                                Remove-Item $file.FullName -Force
                                Write-Log "Removed $($file.FullName)" 'SUCCESS'
                                $Global:ErasedItems += $file.FullName
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to process Spotify file $($file.FullName): $_" 'ERROR'
                    $Global:FailedItems += $file.FullName
                }
            }
        }
    }
}

# Epic Games / EOS Token Erasure
function Remove-EpicGamesTokens {
    Write-Log "=== Epic Games / EOS Token Erasure ===" 'INFO'
    
    # Epic Games stores refresh tokens in OS credential store
    # This function focuses on app data and configuration
    $epicPaths = @(
        "$env:LOCALAPPDATA\EpicGamesLauncher",
        "$env:APPDATA\EpicGamesLauncher",
        "$env:LOCALAPPDATA\EOS",
        "$env:APPDATA\EOS"
    )
    
    foreach ($basePath in $epicPaths) {
        if (-not (Test-PathSafe $basePath)) { continue }
        
        $configFiles = Get-ChildItem "$basePath\*\*.ini" -ErrorAction SilentlyContinue
        $jsonFiles = Get-ChildItem "$basePath\*\*.json" -ErrorAction SilentlyContinue
        
        foreach ($file in ($configFiles + $jsonFiles)) {
            try {
                $content = Get-Content $file.FullName -Raw
                $tokens = Find-TokensInContent $content $file.FullName
                
                if ($tokens.Count -gt 0) {
                    Write-Log "Found $($tokens.Count) tokens in Epic Games file: $($file.FullName)" 'WARNING'
                    $Global:FoundTokens += $tokens
                    
                    if (-not $DryRun) {
                        if ($SecureWipe) {
                            if (Secure-WipeFile $file.FullName $WipePasses) {
                                Write-Log "Securely wiped $($file.FullName)" 'SUCCESS'
                                $Global:ErasedItems += $file.FullName
                            }
                        } else {
                            Remove-Item $file.FullName -Force
                            Write-Log "Removed $($file.FullName)" 'SUCCESS'
                            $Global:ErasedItems += $file.FullName
                        }
                    }
                }
            }
            catch {
                Write-Log "Failed to process Epic Games file $($file.FullName): $_" 'ERROR'
            }
        }
    }
}

# Discord Token Erasure
function Remove-DiscordTokens {
    Write-Log "=== Discord Token Erasure ===" 'INFO'
    
    $discordPaths = @(
        "$env:LOCALAPPDATA\Discord",
        "$env:APPDATA\discord",
        "$env:LOCALAPPDATA\discordcanary",
        "$env:APPDATA\discordcanary"
    )
    
    foreach ($basePath in $discordPaths) {
        if (-not (Test-PathSafe $basePath)) { continue }
        
        # Discord uses LevelDB in Local Storage
        $leveldbPath = "$basePath\app-*\Local Storage\leveldb"
        $leveldbFolders = Get-ChildItem $leveldbPath -ErrorAction SilentlyContinue
        
        foreach ($folder in $leveldbFolders) {
            $tokens = Search-LevelDBForTokens $folder.FullName
            if ($tokens.Count -gt 0) {
                Write-Log "Found $($tokens.Count) tokens in Discord LevelDB: $($folder.FullName)" 'WARNING'
                $Global:FoundTokens += $tokens
                
                if (-not $DryRun) {
                    if ($SecureWipe) {
                        # Remove all files in LevelDB folder with secure wipe
                        $leveldbFiles = Get-ChildItem $folder.FullName -File
                        foreach ($file in $leveldbFiles) {
                            if (Secure-WipeFile $file.FullName $WipePasses) {
                                Write-Log "Securely wiped Discord LevelDB file: $($file.FullName)" 'SUCCESS'
                                $Global:ErasedItems += $file.FullName
                            }
                        }
                    } else {
                        Remove-Item $folder.FullName -Recurse -Force
                        Write-Log "Removed Discord LevelDB folder: $($folder.FullName)" 'SUCCESS'
                        $Global:ErasedItems += $folder.FullName
                    }
                }
            }
        }
    }
}

# Battle.net Token Erasure
function Remove-BattleNetTokens {
    Write-Log "=== Battle.net Token Erasure ===" 'INFO'
    
    $battlenetPaths = @(
        "$env:PROGRAMFILES (x86)\Battle.net",
        "$env:LOCALAPPDATA\Battle.net",
        "$env:APPDATA\Battle.net"
    )
    
    foreach ($basePath in $battlenetPaths) {
        if (-not (Test-PathSafe $basePath)) { continue }
        
        # Battle.net registry keys
        $battlenetRegKeys = @(
            @{ Hive = 'HKEY_LOCAL_MACHINE'; Path = 'SOFTWARE\WOW6432Node\Battle.net' },
            @{ Hive = 'HKEY_CURRENT_USER'; Path = 'SOFTWARE\Battle.net' }
        )
        
        foreach ($regKey in $battlenetRegKeys) {
            try {
                $regPath = "$($regKey.Hive)\$($regKey.Path)"
                if (Test-Path "Registry::$regPath") {
                    $properties = Get-ItemProperty "Registry::$regPath" -ErrorAction SilentlyContinue
                    foreach ($property in $properties.PSObject.Properties.Name) {
                        if ($property -like "*token*" -or $property -like "*auth*" -or $property -like "*session*" -or $property -like "*cookie*") {
                            Write-Log "Found Battle.net registry property: $property" 'WARNING'
                            if (-not $DryRun) {
                                Remove-RegistryValue $regKey.Hive $regKey.Path $property
                                Write-Log "Removed Battle.net registry value: $property" 'SUCCESS'
                                $Global:ErasedItems += "$regPath\$property"
                            }
                        }
                    }
                }
            }
            catch {
                Write-Log "Failed to process Battle.net registry key $($regKey.Path) : $_" 'ERROR'
            }
        }
        
        # Battle.net app data files
        $configFiles = Get-ChildItem "$basePath\*.battlenet*" -ErrorAction SilentlyContinue
        foreach ($file in $configFiles) {
            try {
                $content = Get-Content $file.FullName -Raw
                $tokens = Find-TokensInContent $content $file.FullName
                
                if ($tokens.Count -gt 0) {
                    Write-Log "Found $($tokens.Count) tokens in Battle.net file: $($file.FullName)" 'WARNING'
                    $Global:FoundTokens += $tokens
                    
                    if (-not $DryRun) {
                        if ($SecureWipe) {
                            if (Secure-WipeFile $file.FullName $WipePasses) {
                                Write-Log "Securely wiped $($file.FullName)" 'SUCCESS'
                                $Global:ErasedItems += $file.FullName
                            }
                        } else {
                            Remove-Item $file.FullName -Force
                            Write-Log "Removed $($file.FullName)" 'SUCCESS'
                            $Global:ErasedItems += $file.FullName
                        }
                    }
                }
            }
            catch {
                Write-Log "Failed to process Battle.net file $($file.FullName): $_" 'ERROR'
            }
        }
    }
}

# Origin (EA App) Token Erasure
function Remove-OriginTokens {
    Write-Log "=== Origin (EA App) Token Erasure ===" 'INFO'
    
    $originPaths = @(
        "$env:PROGRAMFILES (x86)\Origin",
        "$env:LOCALAPPDATA\Origin",
        "$env:APPDATA\Origin"
    )
    
    foreach ($basePath in $originPaths) {
        if (-not (Test-PathSafe $basePath)) { continue }
        
        # Origin configuration files
        $configFiles = @(
            "$basePath\local.xml",
            "$basePath\override.cfg",
            "$basePath\ThinSetup\thinsetup.cfg"
        )
        
        foreach ($configFile in $configFiles) {
            if (Test-PathSafe $configFile) {
                try {
                    $content = Get-Content $configFile -Raw
                    $tokens = Find-TokensInContent $content $configFile
                    
                    if ($tokens.Count -gt 0) {
                        Write-Log "Found $($tokens.Count) tokens in Origin file: $configFile" 'WARNING'
                        $Global:FoundTokens += $tokens
                        
                        if (-not $DryRun) {
                            if ($SecureWipe) {
                                if (Secure-WipeFile $configFile $WipePasses) {
                                    Write-Log "Securely wiped $configFile" 'SUCCESS'
                                    $Global:ErasedItems += $configFile
                                }
                            } else {
                                Remove-Item $configFile -Force
                                Write-Log "Removed $configFile" 'SUCCESS'
                                $Global:ErasedItems += $configFile
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to process Origin file $configFile : $_" 'ERROR'
                    $Global:FailedItems += $configFile
                }
            }
        }
    }
}

# Ubisoft Connect (uPlay) Token Erasure
function Remove-UbisoftTokens {
    Write-Log "=== Ubisoft Connect (uPlay) Token Erasure ===" 'INFO'
    
    $uplayPaths = @(
        "$env:PROGRAMFILES (x86)\Ubisoft\Ubisoft Game Launcher",
        "$env:LOCALAPPDATA\UbisoftGameLauncher",
        "$env:APPDATA\UbisoftGameLauncher"
    )
    
    foreach ($basePath in $uplayPaths) {
        if (-not (Test-PathSafe $basePath)) { continue }
        
        # Ubisoft Connect configuration
        $configFiles = @(
            "$basePath\data.config",
            "$basePath\settings.json",
            "$basePath\UplaySettings.ini"
        )
        
        foreach ($configFile in $configFiles) {
            if (Test-PathSafe $configFile) {
                try {
                    $content = Get-Content $configFile -Raw
                    $tokens = Find-TokensInContent $content $configFile
                    
                    if ($tokens.Count -gt 0) {
                        Write-Log "Found $($tokens.Count) tokens in Ubisoft file: $configFile" 'WARNING'
                        $Global:FoundTokens += $tokens
                        
                        if (-not $DryRun) {
                            if ($SecureWipe) {
                                if (Secure-WipeFile $configFile $WipePasses) {
                                    Write-Log "Securely wiped $configFile" 'SUCCESS'
                                    $Global:ErasedItems += $configFile
                                }
                            } else {
                                Remove-Item $configFile -Force
                                Write-Log "Removed $configFile" 'SUCCESS'
                                $Global:ErasedItems += $configFile
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to process Ubisoft file $configFile : $_" 'ERROR'
                    $Global:FailedItems += $configFile
                }
            }
        }
    }
}

# Adobe Creative Cloud Token Erasure
function Remove-AdobeTokens {
    Write-Log "=== Adobe Creative Cloud Token Erasure ===" 'INFO'
    
    $adobePaths = @(
        "$env:LOCALAPPDATA\Adobe",
        "$env:APPDATA\Adobe",
        "$env:PROGRAMFILES\Adobe",
        "$env:PROGRAMFILES (x86)\Adobe"
    )
    
    foreach ($basePath in $adobePaths) {
        if (-not (Test-PathSafe $basePath)) { continue }
        
        # Adobe CC configuration and cache
        $tokenFiles = @(
            "$basePath\AdobeOOBE\*\Config\*",
            "$basePath\Adobe PCD\*\Cache\*",
            "$basePath\CCX*\*\Cache\*",
            "$basePath\LogTransport2\*"
        )
        
        foreach ($pattern in $tokenFiles) {
            $files = Get-ChildItem $pattern -Include "*.json", "*.xml", "*.config", "*.db" -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                try {
                    $content = Get-Content $file.FullName -Raw
                    $tokens = Find-TokensInContent $content $file.FullName
                    
                    if ($tokens.Count -gt 0) {
                        Write-Log "Found $($tokens.Count) tokens in Adobe file: $($file.FullName)" 'WARNING'
                        $Global:FoundTokens += $tokens
                        
                        if (-not $DryRun) {
                            if ($SecureWipe) {
                                if (Secure-WipeFile $file.FullName $WipePasses) {
                                    Write-Log "Securely wiped $($file.FullName)" 'SUCCESS'
                                    $Global:ErasedItems += $file.FullName
                                }
                            } else {
                                Remove-Item $file.FullName -Force
                                Write-Log "Removed $($file.FullName)" 'SUCCESS'
                                $Global:ErasedItems += $file.FullName
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to process Adobe file $($file.FullName): $_" 'ERROR'
                    $Global:FailedItems += $file.FullName
                }
            }
        }
    }
}

# Office 365 / Microsoft Store Apps Token Erasure
function Remove-Office365Tokens {
    Write-Log "=== Office 365 / Microsoft Store Apps Token Erasure ===" 'INFO'
    
    $office365Paths = @(
        "$env:LOCALAPPDATA\Microsoft\Office",
        "$env:APPDATA\Microsoft\Office",
        "$env:LOCALAPPDATA\Microsoft\OneNote",
        "$env:APPDATA\Microsoft\OneNote"
    )
    
    foreach ($basePath in $office365Paths) {
        if (-not (Test-PathSafe $basePath)) { continue }
        
        # Office 365 token files
        $tokenFiles = @(
            "$basePath\16.0\*.OLS",
            "$basePath\16.0\*.CACH",
            "$basePath\16.0\*.TKN"
        )
        
        foreach ($pattern in $tokenFiles) {
            $files = Get-ChildItem $pattern -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                Write-Log "Found Office 365 token file: $($file.FullName)" 'WARNING'
                
                if (-not $DryRun) {
                    if ($SecureWipe) {
                        if (Secure-WipeFile $file.FullName $WipePasses) {
                            Write-Log "Securely wiped $($file.FullName)" 'SUCCESS'
                            $Global:ErasedItems += $file.FullName
                        }
                    } else {
                        Remove-Item $file.FullName -Force
                        Write-Log "Removed $($file.FullName)" 'SUCCESS'
                        $Global:ErasedItems += $file.FullName
                    }
                }
            }
        }
    }
    
    # Windows Credential Manager cleanup
    try {
        $credManItems = & cmdkey.exe /list | Select-String "Target:" | ForEach-Object { $_.Line }
        foreach ($item in $credManItems) {
            if ($item -match "Target:\s*(.*)") {
                $target = $matches[1]
                if ($target -match "(office|microsoft|office365|onedrive|teams|outlook|excel|powerpoint|word)") {
                    Write-Log "Found Office/Microsoft credential: $target" 'WARNING'
                    if (-not $DryRun) {
                        & cmdkey.exe /delete:$target | Out-Null
                        Write-Log "Deleted Office/Microsoft credential: $target" 'SUCCESS'
                        $Global:ErasedItems += "CredentialManager:$target"
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Failed to access Windows Credential Manager: $_" 'ERROR'
    }
}

# GitHub/GitLab PAT Erasure
function Remove-GitTokens {
    Write-Log "=== GitHub/GitLab PAT Erasure ===" 'INFO'
    
    $gitPaths = @(
        "$env:LOCALAPPDATA\GitHubDesktop",
        "$env:APPDATA\GitHubDesktop",
        "$env:LOCALAPPDATA\GitLabDesktop",
        "$env:APPDATA\GitLabDesktop"
    )
    
    foreach ($basePath in $gitPaths) {
        if (-not (Test-PathSafe $basePath)) { continue }
        
        # Git credential helper storage
        $gitconfigPaths = @(
            "$env:USERPROFILE\.gitconfig",
            "$env:LOCALAPPDATA\Programs\Git\etc\gitconfig",
            "$basePath\resources\app\static\licenses\**\gitconfig"
        )
        
        foreach ($gitconfig in $gitconfigPaths) {
            if (Test-PathSafe $gitconfig) {
                try {
                    $content = Get-Content $gitconfig -Raw
                    $tokens = Find-TokensInContent $content $gitconfig $TokenPatterns.PAT
                    
                    if ($tokens.Count -gt 0) {
                        Write-Log "Found $($tokens.Count) PAT tokens in Git config: $gitconfig" 'WARNING'
                        $Global:FoundTokens += $tokens
                        
                        if (-not $DryRun) {
                            if ($SecureWipe) {
                                if (Secure-WipeFile $gitconfig $WipePasses) {
                                    Write-Log "Securely wiped $gitconfig" 'SUCCESS'
                                    $Global:ErasedItems += $gitconfig
                                }
                            } else {
                                Remove-Item $gitconfig -Force
                                Write-Log "Removed $gitconfig" 'SUCCESS'
                                $Global:ErasedItems += $gitconfig
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to process Git config $gitconfig : $_" 'ERROR'
                }
            }
        }
    }
    
    # Windows Credential Manager GitHub/GitLab entries
    try {
        $credManItems = & cmdkey.exe /list | Select-String "Target:" | ForEach-Object { $_.Line }
        foreach ($item in $credManItems) {
            if ($item -match "Target:\s*(.*)") {
                $target = $matches[1]
                if ($target -match "(github|gitlab|bitbucket|git:)" -or $target -like "*pat*") {
                    Write-Log "Found Git credential: $target" 'WARNING'
                    if (-not $DryRun) {
                        & cmdkey.exe /delete:$target | Out-Null
                        Write-Log "Deleted Git credential: $target" 'SUCCESS'
                        $Global:ErasedItems += "CredentialManager:$target"
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Failed to access Git credentials in Credential Manager: $_" 'ERROR'
    }
}

# VS Code Extension and Git Token Erasure
function Remove-VSCodeTokens {
    Write-Log "=== VS Code Extension and Git Token Erasure ===" 'INFO'
    
    $vscodePaths = @(
        "$env:LOCALAPPDATA\Programs\Microsoft VS Code",
        "$env:USERPROFILE\.vscode",
        "$env:APPDATA\Code\User"
    )
    
    foreach ($basePath in $vscodePaths) {
        if (-not (Test-PathSafe $basePath)) { continue }
        
        # VS Code user settings and extensions
        $vscodeFiles = @(
            "$basePath\settings.json",
            "$basePath\keybindings.json",
            "$basePath\extensions\**\package.json",
            "$basePath\extensions\**\*.vsix"
        )
        
        foreach ($pattern in $vscodeFiles) {
            $files = Get-ChildItem $pattern -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                try {
                    $content = Get-Content $file.FullName -Raw
                    $tokens = Find-TokensInContent $content $file.FullName
                    
                    if ($tokens.Count -gt 0) {
                        Write-Log "Found $($tokens.Count) tokens in VS Code file: $($file.FullName)" 'WARNING'
                        $Global:FoundTokens += $tokens
                        
                        if (-not $DryRun) {
                            if ($SecureWipe) {
                                if (Secure-WipeFile $file.FullName $WipePasses) {
                                    Write-Log "Securely wiped $($file.FullName)" 'SUCCESS'
                                    $Global:ErasedItems += $file.FullName
                                }
                            } else {
                                Remove-Item $file.FullName -Force
                                Write-Log "Removed $($file.FullName)" 'SUCCESS'
                                $Global:ErasedItems += $file.FullName
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to process VS Code file $($file.FullName): $_" 'ERROR'
                    $Global:FailedItems += $file.FullName
                }
            }
        }
    }
}

# Browser Token Erasure (if requested)
function Remove-BrowserTokens {
    if (-not $IncludeBrowserData) {
        return
    }
    
    Write-Log "=== Browser Token Erasure (Chrome, Edge, Firefox) ===" 'INFO'
    
    $browserPaths = @{
        'Chrome' = @(
            "$env:LOCALAPPDATA\Google\Chrome\User Data",
            "$env:APPDATA\Google\Chrome\User Data"
        )
        'Edge' = @(
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
            "$env:APPDATA\Microsoft\Edge\User Data"
        )
        'Firefox' = @(
            "$env:APPDATA\Mozilla\Firefox\Profiles"
        )
    }
    
    foreach ($browser in $browserPaths.Keys) {
        foreach ($basePath in $browserPaths[$browser]) {
            if (-not (Test-PathSafe $basePath)) { continue }
            
            # Browser storage files
            $storageFiles = @(
                "$basePath\**\Local Storage\*.ldb",
                "$basePath\**\Session Storage\*.ldb",
                "$basePath\**\Databases\*.ldb",
                "$basePath\**\Cookies*",
                "$basePath\**\Preferences"
            )
            
            foreach ($pattern in $storageFiles) {
                $files = Get-ChildItem $pattern -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    try {
                        # Search for OAuth tokens and session data
                        $content = [System.IO.File]::ReadAllBytes($file.FullName)
                        $textContent = [System.Text.Encoding]::UTF8.GetString($content)
                        $tokens = Find-TokensInContent $textContent $file.FullName
                        
                        if ($tokens.Count -gt 0) {
                            Write-Log "Found $($tokens.Count) tokens in $browser file: $($file.FullName)" 'WARNING'
                            $Global:FoundTokens += $tokens
                            
                            if (-not $DryRun) {
                                if ($SecureWipe) {
                                    if (Secure-WipeFile $file.FullName $WipePasses) {
                                        Write-Log "Securely wiped $($file.FullName)" 'SUCCESS'
                                        $Global:ErasedItems += $file.FullName
                                    }
                                } else {
                                    Remove-Item $file.FullName -Force
                                    Write-Log "Removed $($file.FullName)" 'SUCCESS'
                                    $Global:ErasedItems += $file.FullName
                                }
                            }
                        }
                    }
                    catch {
                        Write-Log "Failed to process $browser file $($file.FullName): $_" 'ERROR'
                        $Global:FailedItems += $file.FullName
                    }
                }
            }
        }
    }
}

# Clean up remaining app data directories
function Remove-CommonAppDataTokens {
    Write-Log "=== Common App Data Token Cleanup ===" 'INFO'
    
    # Clean up various app data directories that commonly contain tokens
    $commonPaths = @(
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp",
        "$env:APPDATA\Temp",
        "$env:USERPROFILE\AppData\Local\Temp"
    )
    
    foreach ($tempPath in $commonPaths) {
        if (-not (Test-PathSafe $tempPath)) { continue }
        
        try {
            # Remove temp files that might contain tokens
            $tempFiles = Get-ChildItem $tempPath -File -Recurse | Where-Object { 
                $_.Extension -match '\.(json|xml|conf|cfg|ini|log|db|sqlite)$' -and 
                $_.Length -lt 10MB 
            }
            
            foreach ($file in $tempFiles) {
                try {
                    $content = Get-Content $file.FullName -Raw
                    $tokens = Find-TokensInContent $content $file.FullName
                    
                    if ($tokens.Count -gt 0) {
                        Write-Log "Found $($tokens.Count) tokens in temp file: $($file.FullName)" 'WARNING'
                        $Global:FoundTokens += $tokens
                        
                        if (-not $DryRun) {
                            if ($SecureWipe) {
                                if (Secure-WipeFile $file.FullName $WipePasses) {
                                    Write-Log "Securely wiped temp file: $($file.FullName)" 'SUCCESS'
                                    $Global:ErasedItems += $file.FullName
                                }
                            } else {
                                Remove-Item $file.FullName -Force
                                Write-Log "Removed temp file: $($file.FullName)" 'SUCCESS'
                                $Global:ErasedItems += $file.FullName
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to process temp file $($file.FullName): $_" 'ERROR'
                }
            }
        }
        catch {
            Write-Log "Failed to process temp directory $tempPath : $_" 'ERROR'
        }
    }
}

# Generate final report
function Generate-Report {
    Write-Log "=== Final Report ===" 'INFO'
    
    $report = @"
========================================
AppTokenEraser - Final Report
Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
========================================
Summary:
- Total tokens found: $($Global:FoundTokens.Count)
- Items successfully erased: $($Global:ErasedItems.Count)
- Items failed: $($Global:FailedItems.Count)
- Mode: $(if ($DryRun) { 'DRY RUN' } else { 'LIVE EXECUTION' })
- Secure wipe passes: $WipePasses

Token Types Found:
"@
    
    # Group tokens by type
    $tokenGroups = $Global:FoundTokens | Group-Object Type | Sort-Object Count -Descending
    foreach ($group in $tokenGroups) {
        $report += "- $($group.Name): $($group.Count)`n"
    }
    
    $report += @"

Erased Items:
"@
    foreach ($item in $Global:ErasedItems) {
        $report += "- $item`n"
    }
    
    if ($Global:FailedItems.Count -gt 0) {
        $report += @"

Failed Items:
"@
        foreach ($item in $Global:FailedItems) {
            $report += "- $item`n"
        }
    }
    
    $report += @"

Recommendations:
1. Restart applications to clear in-memory tokens
2. Clear browser data and cookies manually if needed
3. Review and update application security settings
4. Consider using password managers instead of stored credentials
5. Monitor for re-creation of token files

Log file saved to: $Global:LogFile
========================================
"@
    
    Add-Content -Path $Global:LogFile -Value $report
    Write-Host $report
    
    return $report
}

# Main execution
function Main {
    Initialize-Logging
    
    Write-Log "Starting AppTokenEraser PowerShell script" 'INFO'
    Write-Log "This tool will search for and remove application tokens and credentials" 'INFO'
    
    if ($DryRun) {
        Write-Log "DRY RUN MODE - No actual deletions will occur" 'WARNING'
    }
    
    if ($SecureWipe) {
        Write-Log "Secure wipe enabled with $WipePasses pass(es) per file" 'INFO'
    }
    
    # Execute all token removal functions
    try {
        Remove-SteamTokens
        Remove-SpotifyTokens
        Remove-EpicGamesTokens
        Remove-DiscordTokens
        Remove-BattleNetTokens
        Remove-OriginTokens
        Remove-UbisoftTokens
        Remove-AdobeTokens
        Remove-Office365Tokens
        Remove-GitTokens
        Remove-VSCodeTokens
        Remove-BrowserTokens
        Remove-CommonAppDataTokens
    }
    catch {
        Write-Log "Error during token removal: $_" 'ERROR'
    }
    
    # Generate final report
    Generate-Report
    
    Write-Log "AppTokenEraser completed" 'SUCCESS'
}

# Start execution
Main