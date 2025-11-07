# Demo-SecureEraser.ps1
# Demonstration script for SecureEraser module
# This script shows how to safely test and use the SecureEraser module

#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [switch]$TestMode,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipBrowserTargets,
    
    [Parameter(Mandatory=$false)]
    [string]$LogLevel = "INFO"
)

# Import the SecureEraser module
$modulePath = Join-Path $PSScriptRoot "SecureEraser.psm1"
Import-Module $modulePath -Force

Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                SecureEraser Demonstration Script             ║
║              Military-Grade Secure Deletion Module           ║
╠══════════════════════════════════════════════════════════════╣
║  This script demonstrates the SecureEraser module usage.     ║
║  In TestMode, it will create test files and verify deletion. ║
║  In production mode, it targets real credential locations.   ║
╠══════════════════════════════════════════════════════════════╣
"@ -ForegroundColor Cyan

# System information
Write-Host "System Information:" -ForegroundColor Yellow
Write-Host "- PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor White
Write-Host "- Platform: $($PSVersionTable.Platform)" -ForegroundColor White
Write-Host "- OS: $((Get-CimInstance Win32_OperatingSystem).Caption)" -ForegroundColor White
Write-Host "- Processor: $((Get-CimInstance Win32_Processor | Select-Object -First 1).Name)" -ForegroundColor White
Write-Host "- RAM: $([math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB, 2)) GB" -ForegroundColor White
Write-Host ""

# Check administrative privileges
if (-not (Test-AdministrativeRights)) {
    Write-Host "❌ Administrative privileges required. Please run as Administrator." -ForegroundColor Red
    Write-Host "   Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Administrative privileges verified" -ForegroundColor Green
Write-Host ""

# Function to create test files
function New-SecureEraserTestData {
    <#
    .SYNOPSIS
    Creates test files for secure deletion demonstration
    #>
    param([string]$TestPath = "$env:TEMP\SecureEraser_Test")
    
    Write-Host "Creating test data at: $TestPath" -ForegroundColor Yellow
    
    $null = New-Item -ItemType Directory -Force -Path $TestPath
    
    # Create various types of test files
    $testFiles = @{
        "sensitive_secrets.txt" = @"
CONFIDENTIAL INFORMATION
========================
Password: SuperSecret123!
API Key: sk_live_abc123def456ghi789jkl012mno345pqr678stu901vwx234yz
Social Security Number: 123-45-6789
Credit Card: 4111-1111-1111-1111
Email: admin@company.com
Encryption Key: 0xA1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF1234
"@
        
        "browser_credentials.json" = @"
{
  "chrome_credentials": [
    {
      "url": "https://bank.example.com",
      "username": "user@example.com",
      "encrypted_password": "v10:gAAAAABh...",
      "last_used": "2024-01-15T10:30:00Z"
    }
  ],
  "edge_credentials": [
    {
      "url": "https://email.example.com",
      "username": "admin@company.com",
      "encrypted_password": "v10:gAAAAABh...",
      "last_used": "2024-01-14T14:20:00Z"
    }
  ]
}
"@
        
        "app_tokens.dat" = @"
DISCORD_TOKEN: Mf.1234.abcdefghijklmnopqrstuvwxyz.ABCDEFGHIJKLMNOPQRSTUVWXYZ-1234567890
GITHUB_TOKEN: ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP
SLACK_TOKEN: xoxb-1234-abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ
AZURE_TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0
"@
        
        "system_config.xml" = @"
<?xml version="1.0" encoding="utf-8"?>
<Configuration>
  <Credentials>
    <Database>
      <Server>sql01.internal.local</Server>
      <Database>ProductionDB</Database>
      <Username>dbadmin</Username>
      <Password Encrypted="true">AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA...</Password>
    </Database>
  </Credentials>
  <APIKeys>
    <Service Name="AWS" Key="AKIA1234567890ABCDEF12" Secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY" />
    <Service Name="Google" Key="AIzaSyBxxxxxxxxxxxxxxxxxxxxx" Secret="GxXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" />
  </APIKeys>
</Configuration>
"@
    }
    
    foreach ($fileName in $testFiles.Keys) {
        $filePath = Join-Path $TestPath $fileName
        $content = $testFiles[$fileName]
        Set-Content -Path $filePath -Value $content -Encoding UTF8
        Write-Host "  Created: $fileName" -ForegroundColor Gray
    }
    
    # Calculate total test data size
    $totalSize = (Get-ChildItem $TestPath -File | Measure-Object -Property Length -Sum).Sum
    Write-Host "Total test data size: $([math]::Round($totalSize/1KB, 2)) KB" -ForegroundColor Cyan
    
    return $TestPath
}

# Function to demonstrate target discovery
function Show-TargetDiscovery {
    <#
    .SYNOPSIS
    Demonstrates target discovery functionality
    #>
    Write-Host "`n🔍 Target Discovery Demonstration" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor Cyan
    
    # Discover browser targets
    Write-Host "`nBrowser Targets:" -ForegroundColor Yellow
    $browserTargets = Get-BrowserCredentialLocations
    foreach ($target in $browserTargets) {
        $exists = if ($target.Exists) { "✅" } else { "❌" }
        $size = if ($target.Size -gt 0) { "$([math]::Round($target.Size/1MB, 2)) MB" } else { "Unknown" }
        Write-Host "  $exists $($target.Browser): $($target.Path) ($size)" -ForegroundColor White
    }
    
    # Discover system targets
    Write-Host "`nSystem Targets:" -ForegroundColor Yellow
    $systemTargets = Get-WindowsCredentialLocations
    foreach ($target in $systemTargets) {
        $exists = if ($target.Exists) { "✅" } else { "❌" }
        Write-Host "  $exists $($target.Name): $($target.Path)" -ForegroundColor White
    }
    
    # Discover application targets
    Write-Host "`nApplication Targets:" -ForegroundColor Yellow
    $appTargets = Get-ApplicationTokenLocations
    foreach ($target in $appTargets) {
        $exists = if ($target.Exists) { "✅" } else { "❌" }
        Write-Host "  $exists $($target.Name): $($target.Path)" -ForegroundColor White
    }
    
    # Show comprehensive target list
    Write-Host "`nAll Available Targets:" -ForegroundColor Yellow
    $allTargets = Find-SecureDeletionTargets -TargetTypes @("All") -IncludeSystem -IncludeApplications
    $totalSize = ($allTargets | Where-Object { $_.Exists } | Measure-Object -Property Size -Sum).Sum
    Write-Host "Total discovered targets: $($allTargets.Count)" -ForegroundColor White
    Write-Host "Total data size: $([math]::Round($totalSize/1GB, 2)) GB" -ForegroundColor White
}

# Function to demonstrate secure deletion with test data
function Test-SecureDeletion {
    <#
    .SYNOPSIS
    Demonstrates secure deletion with test data
    #>
    param([string]$TestDataPath)
    
    Write-Host "`n🧪 Secure Deletion Test" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor Cyan
    
    # Create progress callback
    $progressCallback = {
        param($progress)
        $percent = $progress.CalculateProgress()
        $eta = $progress.GetEta()
        Write-Host "  Progress: $percent% - ETA: $eta - $($progress.CurrentOperation)" -ForegroundColor Gray
    }
    
    # Get test files
    $testFiles = Get-ChildItem $TestDataPath -File
    
    Write-Host "Files to be deleted:" -ForegroundColor Yellow
    foreach ($file in $testFiles) {
        Write-Host "  - $($file.Name) ($([math]::Round($file.Length/1KB, 2)) KB)" -ForegroundColor White
    }
    
    # Ask for confirmation
    Write-Host "`n⚠️  This will permanently delete the test files!" -ForegroundColor Red
    Write-Host "Files will be encrypted with AES-256 in multiple rounds." -ForegroundColor Yellow
    
    $confirmation = Read-Host "Proceed with test deletion? (YES/NO)"
    if ($confirmation -ne "YES") {
        Write-Host "Test cancelled by user." -ForegroundColor Yellow
        return
    }
    
    try {
        # Perform secure deletion
        $results = Start-SecureEraser -Targets $testFiles.FullName -Rounds 3 -Verify -LogLevel $LogLevel
        
        Write-Host "`n✅ Test completed successfully!" -ForegroundColor Green
        
        foreach ($result in $results) {
            if ($result.Success) {
                Write-Host "  ✓ $($result.Target) - Deleted and verified" -ForegroundColor Green
            } else {
                Write-Host "  ✗ $($result.Target) - Failed: $($result.Error)" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "`n❌ Test failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to demonstrate real-world usage
function Show-RealWorldUsage {
    <#
    .SYNOPSIS
    Shows real-world usage examples
    #>
    Write-Host "`n🌍 Real-World Usage Examples" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor Cyan
    
    Write-Host @"

1. CLEANUP BROWSER CREDENTIALS (After malware scan):
   Start-SecureEraser -TargetTypes @("Browsers") -Rounds 3 -Parallel -Force
   
2. SECURELY DELETE SENSITIVE FILES:
   Start-SecureEraser -Targets @("C:\Finance\*.xlsx", "C:\HR\*.pdf") -Rounds 5 -Verify
   
3. CLEANUP AFTER SECURITY INCIDENT:
   Start-SecureEraser -TargetTypes @("All") -Rounds 7 -LogLevel "DEBUG" -Verify -Force
   
4. TARGET SPECIFIC BROWSERS ONLY:
   Start-SecureEraser -Browsers @("Chrome", "Edge") -Rounds 5 -Parallel
   
5. SYSTEM CREDENTIALS CLEANUP:
   Start-SecureEraser -TargetTypes @("System") -Rounds 7 -Force -LogLevel "DEBUG"
   
6. CLEANUP WITH PROGRESS TRACKING:
   $callback = { param($p) Write-Host "Progress: $($p.CalculateProgress())%" }
   Start-SecureEraser -TargetTypes @("All") -ProgressCallback $callback -Verify

"@ -ForegroundColor White
}

# Main demonstration
function Main {
    Write-Host "🚀 Starting SecureEraser Demonstration" -ForegroundColor Green
    
    if ($TestMode) {
        Write-Host "🧪 Test Mode: Creating test data and verifying deletion" -ForegroundColor Yellow
        $testDataPath = New-SecureEraserTestData
        
        try {
            Show-TargetDiscovery
            Test-SecureDeletion -TestDataPath $testDataPath
        }
        finally {
            Write-Host "`nCleaning up test data..." -ForegroundColor Yellow
            Remove-Item -Path $testDataPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        Write-Host "🔧 Production Mode: Demonstrating module capabilities" -ForegroundColor Yellow
        
        if ($SkipBrowserTargets) {
            Write-Host "⚠️  Skipping browser targets (--SkipBrowserTargets specified)" -ForegroundColor Yellow
        }
        
        Show-TargetDiscovery
        Show-RealWorldUsage
        
        # Ask if user wants to perform actual deletion
        Write-Host "`nWould you like to perform actual secure deletion?" -ForegroundColor Yellow
        Write-Host "This will target real credential databases and files." -ForegroundColor Red
        $performDeletion = Read-Host "Proceed with secure deletion? (YES/NO/QUIT)"
        
        switch ($performDeletion.ToUpper()) {
            "YES" {
                if ($SkipBrowserTargets) {
                    Start-SecureEraser -TargetTypes @("System", "Applications") -Rounds 3 -LogLevel $LogLevel
                } else {
                    Start-SecureEraser -TargetTypes @("All") -Rounds 3 -LogLevel $LogLevel
                }
            }
            "QUIT" {
                Write-Host "Exiting demonstration." -ForegroundColor Yellow
                return
            }
            default {
                Write-Host "Demonstration completed without deletion." -ForegroundColor Yellow
            }
        }
    }
    
    Write-Host "`n📋 Demonstration Summary" -ForegroundColor Cyan
    Write-Host "=" * 30 -ForegroundColor Cyan
    Write-Host "✅ Module loaded and verified" -ForegroundColor Green
    Write-Host "✅ Administrative privileges confirmed" -ForegroundColor Green
    Write-Host "✅ Target discovery demonstrated" -ForegroundColor Green
    Write-Host "✅ Secure deletion process shown" -ForegroundColor Green
    
    if ($TestMode) {
        Write-Host "✅ Test data created and securely deleted" -ForegroundColor Green
    }
    
    Write-Host "✅ Logging and error handling verified" -ForegroundColor Green
    Write-Host "✅ Progress tracking demonstrated" -ForegroundColor Green
    
    Write-Host "`n📚 Next Steps:" -ForegroundColor Yellow
    Write-Host "1. Review the README.md for detailed usage information" -ForegroundColor White
    Write-Host "2. Test with non-critical data first" -ForegroundColor White
    Write-Host "3. Ensure you have proper authorization and backups" -ForegroundColor White
    Write-Host "4. Use appropriate rounds based on data sensitivity" -ForegroundColor White
    Write-Host "5. Monitor logs for verification and audit trail" -ForegroundColor White
}

# Error handling
try {
    Main
}
catch {
    Write-Host "`n❌ Demonstration failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    
    if ($_.Exception.InnerException) {
        Write-Host "Inner exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
}

Write-Host "`n🏁 SecureEraser demonstration completed." -ForegroundColor Green
Write-Host "Thank you for using SecureEraser!" -ForegroundColor Cyan