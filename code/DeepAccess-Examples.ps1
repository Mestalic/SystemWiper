#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Examples of using the DeepAccess PowerShell module

.DESCRIPTION
    This file demonstrates various usage patterns for the DeepAccess module
    functions for advanced Windows 11 system access.

.NOTES
    These examples are for educational and legitimate system administration purposes.
    Run this in an isolated test environment with proper backup procedures.
#>

# Import the DeepAccess module
Import-Module .\DeepAccess.ps1 -Force

Write-Host "=== DeepAccess Module Examples ===" -ForegroundColor Cyan
Write-Host ""

# Example 1: Get system access summary
Write-Host "[1] Getting comprehensive system access summary..." -ForegroundColor Yellow
$summ = Get-SystemAccessSummary
Write-Host "Current User: $($summ.SystemInfo.CurrentUser)"
Write-Host "OS: $($summ.SystemInfo.OSName)"
Write-Host "LSASS Protection: $($summ.LSASSProtection.LSAProtection)"
Write-Host "Credential Guard: $($summ.LSASSProtection.CredentialGuard)"
Write-Host ""

# Example 2: Check current privileges
Write-Host "[2] Checking current process privileges..." -ForegroundColor Yellow
$privs = Get-CurrentPrivileges
Write-Host "User: $($privs.User)"
Write-Host "Is Administrator: $($privs.IsAdministrator)"
Write-Host "Available Privileges:"
foreach ($priv in $privs.Privileges) {
    Write-Host "  - $priv"
}
Write-Host ""

# Example 3: Test specific privilege
Write-Host "[3] Testing SeBackupPrivilege..." -ForegroundColor Yellow
$backupTest = Test-Privilege "SeBackupPrivilege"
Write-Host "Has Privilege: $($backupTest.HasPrivilege)"
Write-Host "Is Enabled: $($backupTest.IsEnabled)"
Write-Host ""

# Example 4: Get LSASS protection status
Write-Host "[4] Checking LSASS protection status..." -ForegroundColor Yellow
$lsassStatus = Get-LSASSProtectionStatus
Write-Host "LSA Protection Enabled: $($lsassStatus.LSAProtection)"
Write-Host "PPL Enabled: $($lsassStatus.PPLEnabled)"
Write-Host "Secure Boot: $($lsassStatus.SecureBoot)"
Write-Host "Credential Guard: $($lsassStatus.CredentialGuard)"
Write-Host ""

# Example 5: List all services
Write-Host "[5] Listing system services..." -ForegroundColor Yellow
$services = Get-SystemServices | Select-Object -First 10
Write-Host "Sample of $($services.Count) services (showing first 10):"
foreach ($svc in $services) {
    Write-Host "  $($svc.Name) - $($svc.State) - Protection: $($svc.ProtectionLevel)"
}
Write-Host ""

# Example 6: Get registry hive information
Write-Host "[6] Getting registry hive information..." -ForegroundColor Yellow
$hives = Get-RegistryHiveInfo
Write-Host "Available hives:"
foreach ($hiveName in $hives.Keys) {
    $hive = $hives[$hiveName]
    Write-Host "  $hiveName"
    Write-Host "    Location: $($hive.Location)"
    Write-Host "    Files: $($hive.Files -join ', ')"
}
Write-Host ""

# Example 7: Get USN journal status
Write-Host "[7] Checking USN journal status..." -ForegroundColor Yellow
try {
    $systemDrive = $env:SystemDrive + "\"
    $journal = Get-USNJournalStatus -VolumePath $systemDrive
    Write-Host "Journal ID: $($journal.UsnJournalID)"
    Write-Host "Max USN: $($journal.MaxUsn)"
    Write-Host "Maximum Size: $($journal.MaximumSize) bytes"
}
catch {
    Write-Host "USN journal not accessible (may not be initialized)" -ForegroundColor Yellow
}
Write-Host ""

# Example 8: Get shadow copies
Write-Host "[8] Checking shadow copies..." -ForegroundColor Yellow
try {
    $shadowCopies = Get-ShadowCopies
    if ($shadowCopies) {
        Write-Host "Found $($shadowCopies.Count) shadow copy(s):"
        foreach ($copy in $shadowCopies) {
            Write-Host "  ID: $($copy.ShadowCopyId)"
            Write-Host "  Volume: $($copy.Volume)"
            Write-Host "  Created: $($copy.CreationTime)"
        }
    }
    else {
        Write-Host "No shadow copies found" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "Shadow copies not accessible" -ForegroundColor Yellow
}
Write-Host ""

# Example 9: Test protected process access
Write-Host "[9] Testing access to LSASS process..." -ForegroundColor Yellow
try {
    $lsass = Get-Process -Name "lsass" -ErrorAction SilentlyContinue
    if ($lsass) {
        $accessTest = Test-ProtectedProcessAccess -ProcessId $lsass.Id
        Write-Host "LSASS Process ID: $($accessTest.ProcessId)"
        Write-Host "Can Open: $($accessTest.CanOpen)"
        Write-Host "Can Read Memory: $($accessTest.CanReadMemory)"
        Write-Host "Is Protected: $($accessTest.IsProtected)"
        if ($accessTest.ProtectionLevel -ne "Unknown") {
            Write-Host "Protection Level: $($accessTest.ProtectionLevel)"
        }
    }
    else {
        Write-Host "LSASS process not found" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "Error testing LSASS access: $_" -ForegroundColor Red
}
Write-Host ""

# Example 10: Test secure file access
Write-Host "[10] Testing secure file access to system file..." -ForegroundColor Yellow
try {
    # Try to access a system file that might be protected
    $system32Path = "$env:SystemRoot\System32\config\sam"
    $fileAccess = Get-SecureFileAccess -FilePath $system32Path -ReadOnly
    Write-Host "File: $($fileAccess.FilePath)"
    Write-Host "Access Granted: $($fileAccess.AccessGranted)"
    Write-Host "Method: $($fileAccess.Method)"
}
catch {
    Write-Host "File access test: $_" -ForegroundColor Yellow
}
Write-Host ""

Write-Host "=== DeepAccess Module Examples Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "NOTE: All operations require Administrator privileges and are logged." -ForegroundColor Yellow
Write-Host "Use these functions responsibly and in accordance with security policies." -ForegroundColor Yellow
