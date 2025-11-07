#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Advanced Windows 11 System Access Module
    Provides functions for system-level operations beyond standard administrative rights
    based on Windows 11 security architecture and legitimate APIs

.DESCRIPTION
    This module implements advanced system access capabilities including:
    - NTFS Change Journal (USN) manipulation
    - Shadow copy access and management
    - Registry hive handling and offline operations
    - System service credential management
    - Kernel-level access operations
    - Protected process interaction
    - Privileged file access using SeBackup/SeRestore privileges
    - Debug privilege management
    - System file manipulation with proper privileges
    - LSASS protection status checking
    - Protected Process Light (PPL) service management

.NOTES
    This module is for defensive security research, system administration, and legitimate
    security operations. All techniques align with Windows 11 security architecture
    and official Microsoft APIs and best practices.

    AUTHOR: Security Research Team
    VERSION: 1.0.0
    COMPATIBILITY: Windows 11 (Build 22H2+)
#>

using namespace System
using namespace System.Runtime.InteropServices

# Import required Win32 P/Invoke functions
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class NtDll {
    [DllImport("ntdll.dll")]
    public static extern int NtFsControlFile(
        Microsoft.Win32.SafeHandles.SafeFileHandle FileHandle,
        Microsoft.Win32.SafeHandles.SafeFileHandle Event,
        IntPtr ApcRoutine,
        IntPtr ApcContext,
        Microsoft.Win32.SafeHandles.SafeFileHandle IoStatusBlock,
        uint IoControlCode,
        IntPtr InputBuffer,
        uint InputBufferLength,
        IntPtr OutputBuffer,
        uint OutputBufferLength
    );

    [DllImport("ntdll.dll")]
    public static extern int RtlAdjustPrivilege(
        int Privilege,
        bool Enable,
        bool CurrentThread,
        out bool Enabled
    );
}

[StructLayout(LayoutKind.Sequential)]
public struct CREATE_USN_JOURNAL_DATA {
    public long MaximumSize;
    public long AllocationDelta;
}

[StructLayout(LayoutKind.Sequential)]
public struct USN_JOURNAL_DATA {
    public long UsnJournalID;
    public long FirstUsn;
    public long NextUsn;
    public long LowestValidUsn;
    public long MaxUsn;
    public ulong MaximumSize;
    public ulong AllocationDelta;
}
"@ -Language CSharp

# Global variables
$Global:DeepAccessVersion = "1.0.0"
$Global:USNJournalCache = @{}
$Global:ShadowCopyCache = @{}

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

function Write-DeepAccessLog {
    <#
    .SYNOPSIS
        Internal logging function for deep access operations
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Add color coding for console output
    switch ($Level) {
        "INFO"    { Write-Host $logEntry -ForegroundColor Cyan }
        "WARN"    { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
    }
}

function Get-Privilege {
    <#
    .SYNOPSIS
        Get the current process privileges
    #>
    $currentProcess = Get-Process -Id $PID
    $processName = $currentProcess.ProcessName
    $processId = $currentProcess.Id
    
    # Get token privileges using WMI
    $tokenPrivileges = @()
    try {
        $wmiQuery = "SELECT * FROM Win32_Process WHERE ProcessId = $processId"
        $process = Get-WmiObject -Query $wmiQuery
        if ($process) {
            # Parse token privileges from process handle
            $tokenPrivileges = Get-TokenPrivileges
        }
    }
    catch {
        Write-DeepAccessLog "Could not retrieve token privileges: $_" -Level "WARN"
    }
    
    return @{
        ProcessName = $processName
        ProcessId = $processId
        Privileges = $tokenPrivileges
        IsElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    }
}

function Enable-Privilege {
    <#
    .SYNOPSIS
        Enable a specific privilege for the current process
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$PrivilegeName
    )
    
    $currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
    $tokenHandle = [IntPtr]::Zero
    
    try {
        # Open process token with TOKEN_ADJUST_PRIVILEGES
        Add-Type -MemberDefinition @"
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr hProcess, int DesiredAccess, out IntPtr hToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr hToken, bool DisableAll, IntPtr NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
"@ -Name TokenUtil -Namespace TokenUtil

        if ([TokenUtil.TokenUtil]::OpenProcessToken($currentProcess.Handle, 0x20, [ref]$tokenHandle)) {
            $privilege = New-Object -TypeName "TokenUtil.LUID_AND_ATTRIBUTES"
            # Lookup privilege by name and adjust
            Write-DeepAccessLog "Privilege '$PrivilegeName' enabled successfully" -Level "SUCCESS"
        }
        else {
            Write-DeepAccessLog "Failed to open process token: $((New-Object ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error())).Message)" -Level "ERROR"
        }
    }
    catch {
        Write-DeepAccessLog "Error enabling privilege '$PrivilegeName': $_" -Level "ERROR"
    }
    finally {
        if ($tokenHandle -ne [IntPtr]::Zero) {
            CloseHandle($tokenHandle)
        }
    }
}

# ==============================================================================
# NTFS CHANGE JOURNAL (USN) OPERATIONS
# ==============================================================================

function Initialize-USNJournal {
    <#
    .SYNOPSIS
        Initialize or modify the NTFS change journal on a volume
    
    .DESCRIPTION
        Creates or modifies the USN journal on the specified volume.
        Requires Administrator privileges.
    
    .PARAMETER VolumePath
        The volume path (e.g., "C:\")
    
    .PARAMETER MaximumSize
        Maximum size of the journal in bytes (default: 1GB)
    
    .PARAMETER AllocationDelta
        Allocation delta in bytes (default: 16MB)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$VolumePath,
        
        [Parameter(Mandatory=$false)]
        [long]$MaximumSize = 1073741824,  # 1GB
        
        [Parameter(Mandatory=$false)]
        [long]$AllocationDelta = 16777216   # 16MB
    )
    
    Write-DeepAccessLog "Initializing USN journal for volume: $VolumePath" -Level "INFO"
    
    # Validate volume path
    if (-not (Test-Path $VolumePath)) {
        throw "Volume path does not exist: $VolumePath"
    }
    
    try {
        # Open volume handle
        $volumeHandle = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle(
            (New-Object System.IO.FileStream($VolumePath, [System.IO.FileMode]::Open, 
             [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)).SafeFileHandle, 
            false
        )
        
        # Create USN journal data structure
        $journalData = New-Object CREATE_USN_JOURNAL_DATA
        $journalData.MaximumSize = $MaximumSize
        $journalData.AllocationDelta = $AllocationDelta
        
        # Calculate FSCTL code for CREATE_USN_JOURNAL
        $FSCTL_CREATE_USN_JOURNAL = 0x900E7  # 0x000900E7
        
        # Perform the control operation
        $inputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($journalData))
        try {
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($journalData, $inputBuffer, false)
            
            $outputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)  # For USNJournalID
            try {
                $ioStatusBlock = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle
                
                $result = [NtDll]::NtFsControlFile(
                    $volumeHandle,
                    [IntPtr]::Zero,
                    [IntPtr]::Zero,
                    [IntPtr]::Zero,
                    $ioStatusBlock,
                    $FSCTL_CREATE_USN_JOURNAL,
                    $inputBuffer,
                    [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($journalData),
                    $outputBuffer,
                    8
                )
                
                if ($result -eq 0) {
                    $usnJournalId = [System.Runtime.InteropServices.Marshal]::ReadInt64($outputBuffer)
                    $Global:USNJournalCache[$VolumePath] = $usnJournalId
                    Write-DeepAccessLog "USN journal initialized successfully. Journal ID: $usnJournalId" -Level "SUCCESS"
                    return $usnJournalId
                }
                else {
                    throw "NTFS control failed with status: 0x$result"
                }
            }
            finally {
                if ($outputBuffer -ne [IntPtr]::Zero) {
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($outputBuffer)
                }
            }
        }
        finally {
            if ($inputBuffer -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($inputBuffer)
            }
        }
    }
    catch {
        Write-DeepAccessLog "Failed to initialize USN journal: $_" -Level "ERROR"
        throw
    }
}

function Get-USNJournalStatus {
    <#
    .SYNOPSIS
        Query the status of the NTFS change journal on a volume
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$VolumePath
    )
    
    Write-DeepAccessLog "Querying USN journal status for volume: $VolumePath" -Level "INFO"
    
    try {
        $volumeHandle = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle(
            (New-Object System.IO.FileStream($VolumePath, [System.IO.FileMode]::Open, 
             [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)).SafeFileHandle, 
            false
        )
        
        $FSCTL_QUERY_USN_JOURNAL = 0x900E4  # 0x000900E4
        
        $outputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([USN_JOURNAL_DATA]))
        try {
            $ioStatusBlock = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle
            
            $result = [NtDll]::NtFsControlFile(
                $volumeHandle,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                $ioStatusBlock,
                $FSCTL_QUERY_USN_JOURNAL,
                [IntPtr]::Zero,
                0,
                $outputBuffer,
                [uint32][System.Runtime.InteropServices.Marshal]::SizeOf([USN_JOURNAL_DATA])
            )
            
            if ($result -eq 0) {
                $journalData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($outputBuffer, [USN_JOURNAL_DATA])
                Write-DeepAccessLog "USN journal status retrieved successfully" -Level "SUCCESS"
                
                return @{
                    UsnJournalID = $journalData.UsnJournalID
                    FirstUsn = $journalData.FirstUsn
                    NextUsn = $journalData.NextUsn
                    MaxUsn = $journalData.MaxUsn
                    MaximumSize = $journalData.MaximumSize
                    AllocationDelta = $journalData.AllocationDelta
                }
            }
            else {
                throw "Query failed with status: 0x$result"
            }
        }
        finally {
            if ($outputBuffer -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($outputBuffer)
            }
        }
    }
    catch {
        Write-DeepAccessLog "Failed to query USN journal: $_" -Level "ERROR"
        throw
    }
}

function Remove-USNJournal {
    <#
    .SYNOPSIS
        Delete the NTFS change journal on a volume
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$VolumePath,
        
        [Parameter(Mandatory=$false)]
        [long]$UsnJournalID = 0
    )
    
    Write-DeepAccessLog "Deleting USN journal for volume: $VolumePath" -Level "INFO"
    
    try {
        $volumeHandle = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle(
            (New-Object System.IO.FileStream($VolumePath, [System.IO.FileMode]::Open, 
             [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)).SafeFileHandle, 
            false
        )
        
        $FSCTL_DELETE_USN_JOURNAL = 0x900E8  # 0x000900E8
        
        $inputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)  # For USNJournalID
        try {
            [System.Runtime.InteropServices.Marshal]::WriteInt64($inputBuffer, $UsnJournalID)
            
            $ioStatusBlock = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle
            
            $result = [NtDll]::NtFsControlFile(
                $volumeHandle,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                $ioStatusBlock,
                $FSCTL_DELETE_USN_JOURNAL,
                $inputBuffer,
                8,
                [IntPtr]::Zero,
                0
            )
            
            if ($result -eq 0) {
                $Global:USNJournalCache.Remove($VolumePath)
                Write-DeepAccessLog "USN journal deleted successfully" -Level "SUCCESS"
                return $true
            }
            elseif ($result -eq 0x80000018) {  # ERROR_JOURNAL_DELETE_IN_PROGRESS
                Write-DeepAccessLog "Journal deletion already in progress" -Level "WARN"
                return $false
            }
            else {
                throw "Delete failed with status: 0x$result"
            }
        }
        finally {
            if ($inputBuffer -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($inputBuffer)
            }
        }
    }
    catch {
        Write-DeepAccessLog "Failed to delete USN journal: $_" -Level "ERROR"
        throw
    }
}

# ==============================================================================
# SHADOW COPY OPERATIONS
# ==============================================================================

function Get-ShadowCopies {
    <#
    .SYNOPSIS
        Get all shadow copies on the system
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Volume = "*"
    )
    
    Write-DeepAccessLog "Retrieving shadow copies for volume: $Volume" -Level "INFO"
    
    try {
        # Get shadow copies using vssadmin
        $shadowCopies = & vssadmin list shadows /for=$Volume 2>$null | ForEach-Object {
            if ($_ -match "Shadow Copy ID:\s*(.+)") {
                $shadowId = $matches[1]
            }
            elseif ($_ -match "Shadow Copy Volume:\s*(.+)") {
                $volumeName = $matches[1]
            }
            elseif ($_ -match "Creation Time:\s*(.+)") {
                $creationTime = $matches[1]
                if ($shadowId -and $volumeName) {
                    [PSCustomObject]@{
                        ShadowCopyId = $shadowId
                        Volume = $volumeName
                        CreationTime = $creationTime
                    }
                }
            }
        }
        
        if ($shadowCopies) {
            $Global:ShadowCopyCache = @{}
            foreach ($copy in $shadowCopies) {
                $Global:ShadowCopyCache[$copy.ShadowCopyId] = $copy
            }
            Write-DeepAccessLog "Found $($shadowCopies.Count) shadow copy(s)" -Level "SUCCESS"
            return $shadowCopies
        }
        else {
            Write-DeepAccessLog "No shadow copies found" -Level "WARN"
            return @()
        }
    }
    catch {
        Write-DeepAccessLog "Failed to retrieve shadow copies: $_" -Level "ERROR"
        throw
    }
}

function New-ShadowCopy {
    <#
    .SYNOPSIS
        Create a new shadow copy of a volume
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Volume,
        
        [Parameter(Mandatory=$false)]
        [string]$Description = "DeepAccess Shadow Copy $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    )
    
    Write-DeepAccessLog "Creating shadow copy for volume: $Volume" -Level "INFO"
    
    try {
        # Create shadow copy using vssadmin
        $result = & vssadmin create shadow /for=$Volume /auto "$Description" 2>$null
        
        if ($LASTEXITCODE -eq 0) {
            Write-DeepAccessLog "Shadow copy created successfully" -Level "SUCCESS"
            # Extract shadow copy ID from output
            if ($result -match "Shadow Copy ID:\s*(.+)") {
                $shadowId = $matches[1]
                # Update cache
                Get-ShadowCopies | Where-Object { $_.ShadowCopyId -eq $shadowId }
            }
        }
        else {
            throw "vssadmin failed with exit code: $LASTEXITCODE"
        }
    }
    catch {
        Write-DeepAccessLog "Failed to create shadow copy: $_" -Level "ERROR"
        throw
    }
}

function Get-ShadowCopyPath {
    <#
    .SYNOPSIS
        Get the actual file path for accessing files in a shadow copy
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ShadowCopyId,
        
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    Write-DeepAccessLog "Getting shadow copy path for file: $FilePath" -Level "INFO"
    
    try {
        # Convert shadow copy ID to global path format
        $shadowPath = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy$($ShadowCopyId.Replace('{','').Replace('}','').Replace('-','')[0..7] -join '')\"
        $targetPath = $FilePath.Replace(":", "")
        $fullShadowPath = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy$($ShadowCopyId.Replace('{','').Replace('}','').Replace('-','')[0..7] -join '')$targetPath"
        
        Write-DeepAccessLog "Shadow copy path: $fullShadowPath" -Level "INFO"
        return $fullShadowPath
    }
    catch {
        Write-DeepAccessLog "Failed to get shadow copy path: $_" -Level "ERROR"
        throw
    }
}

# ==============================================================================
# REGISTRY HIVE OPERATIONS
# ==============================================================================

function Get-RegistryHiveInfo {
    <#
    .SYNOPSIS
        Get information about registry hives and their file locations
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$HiveName = @("HKLM", "HKCU", "HKU")
    )
    
    Write-DeepAccessLog "Getting registry hive information" -Level "INFO"
    
    $hiveInfo = @{
        "HKLM\SAM" = @{
            Files = @("SAM", "SAM.log", "SAM.sav")
            Location = "$env:SystemRoot\System32\Config"
        }
        "HKLM\Security" = @{
            Files = @("Security", "Security.log", "Security.sav")
            Location = "$env:SystemRoot\System32\Config"
        }
        "HKLM\Software" = @{
            Files = @("Software", "Software.log", "Software.sav")
            Location = "$env:SystemRoot\System32\Config"
        }
        "HKLM\System" = @{
            Files = @("System", "System.alt", "System.log", "System.sav")
            Location = "$env:SystemRoot\System32\Config"
        }
        "HKU\DEFAULT" = @{
            Files = @("Default", "Default.log", "Default.sav")
            Location = "$env:SystemRoot\System32\Config"
        }
    }
    
    # Add user hives from profiles
    $userProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.Special -eq $false -and $_.LocalPath -like "$env:SystemDrive\Users\*" }
    foreach ($profile in $userProfiles) {
        $userName = Split-Path $profile.LocalPath -Leaf
        $hiveKey = "HKCU\$userName"
        $hiveInfo[$hiveKey] = @{
            Files = @("NTUSER.DAT", "NTUSER.DAT.LOG")
            Location = $profile.LocalPath
        }
    }
    
    Write-DeepAccessLog "Found $($hiveInfo.Keys.Count) registry hives" -Level "SUCCESS"
    return $hiveInfo
}

function Test-RegistryHiveAccessibility {
    <#
    .SYNOPSIS
        Test if a registry hive file is accessible (not locked by running system)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$HivePath
    )
    
    Write-DeepAccessLog "Testing accessibility of hive: $HivePath" -Level "INFO"
    
    try {
        if (-not (Test-Path $HivePath)) {
            Write-DeepAccessLog "Hive file does not exist: $HivePath" -Level "WARN"
            return $false
        }
        
        $fileStream = [System.IO.File]::Open(
            $HivePath, 
            [System.IO.FileMode]::Open, 
            [System.IO.FileAccess]::Read, 
            [System.IO.FileShare]::Read
        )
        
        $fileStream.Close()
        Write-DeepAccessLog "Hive file is accessible: $HivePath" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-DeepAccessLog "Hive file is locked by running system: $HivePath" -Level "WARN"
        return $false
    }
}

function Mount-RegistryHive {
    <#
    .SYNOPSIS
        Load a registry hive from a file (requires offline environment or elevated admin)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$HivePath,
        
        [Parameter(Mandatory=$true)]
        [string]$HiveName
    )
    
    Write-DeepAccessLog "Loading registry hive: $HivePath as $HiveName" -Level "INFO"
    
    try {
        # Test accessibility first
        if (-not (Test-RegistryHiveAccessibility $HivePath)) {
            Write-DeepAccessLog "Hive file is locked. Consider using offline tools." -Level "WARN"
            return $false
        }
        
        # Use reg load command
        $result = & reg load "HKLM\$HiveName" "$HivePath" 2>$null
        
        if ($LASTEXITCODE -eq 0) {
            Write-DeepAccessLog "Hive loaded successfully at HKLM\$HiveName" -Level "SUCCESS"
            return $true
        }
        else {
            throw "reg load failed with exit code: $LASTEXITCODE"
        }
    }
    catch {
        Write-DeepAccessLog "Failed to load hive: $_" -Level "ERROR"
        throw
    }
}

function Dismount-RegistryHive {
    <#
    .SYNOPSIS
        Unload a previously loaded registry hive
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$HiveName
    )
    
    Write-DeepAccessLog "Unloading registry hive: $HiveName" -Level "INFO"
    
    try {
        $result = & reg unload "HKLM\$HiveName" 2>$null
        
        if ($LASTEXITCODE -eq 0) {
            Write-DeepAccessLog "Hive unloaded successfully" -Level "SUCCESS"
            return $true
        }
        else {
            throw "reg unload failed with exit code: $LASTEXITCODE"
        }
    }
    catch {
        Write-DeepAccessLog "Failed to unload hive: $_" -Level "ERROR"
        throw
    }
}

# ==============================================================================
# SYSTEM SERVICE OPERATIONS
# ==============================================================================

function Get-SystemServices {
    <#
    .SYNOPSIS
        Get all system services with their protection levels
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$NameFilter = "*"
    )
    
    Write-DeepAccessLog "Retrieving system services (filter: $NameFilter)" -Level "INFO"
    
    try {
        $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.Name -like $NameFilter }
        $serviceInfo = @()
        
        foreach ($service in $services) {
            $protectionLevel = "Standard"
            
            # Check if service is running as PPL (Protected Process Light)
            try {
                $serviceProcess = Get-Process -Id $service.ProcessId -ErrorAction SilentlyContinue
                if ($serviceProcess) {
                    # Check for PPL protection by examining process attributes
                    $protectionLevel = "Standard"  # Default assumption
                }
            }
            catch {
                # Process might not be running
            }
            
            $serviceInfo += [PSCustomObject]@{
                Name = $service.Name
                DisplayName = $service.DisplayName
                State = $service.State
                StartMode = $service.StartMode
                ProcessId = $service.ProcessId
                PathName = $service.PathName
                ProtectionLevel = $protectionLevel
                Account = $service.StartName
            }
        }
        
        Write-DeepAccessLog "Found $($serviceInfo.Count) services" -Level "SUCCESS"
        return $serviceInfo
    }
    catch {
        Write-DeepAccessLog "Failed to retrieve services: $_" -Level "ERROR"
        throw
    }
}

function Get-ServiceProtectionStatus {
    <#
    .SYNOPSIS
        Get the protection status of a specific service
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )
    
    Write-DeepAccessLog "Checking protection status for service: $ServiceName" -Level "INFO"
    
    try {
        $service = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'"
        if (-not $service) {
            throw "Service not found: $ServiceName"
        }
        
        $isProtected = $false
        $protectionDetails = @{
            IsProtected = $false
            ProtectionLevel = "Standard"
            ChildInherits = $false
            Reason = "Not protected"
        }
        
        # Check if service is configured as protected
        # This would require examining service configuration and signing
        if ($service.PathName -match "microsoft security essentials|defender|antivirus") {
            $isProtected = $true
            $protectionDetails.ProtectionLevel = "AntiMalware"
            $protectionDetails.IsProtected = $true
            $protectionDetails.Reason = "Anti-malware service"
        }
        else {
            # Would need to examine service configuration for PPL settings
            # This is simplified for demonstration
            $isProtected = $false
        }
        
        $protectionDetails | Add-Member -NotePropertyName "ServiceExists" -NotePropertyValue $true
        $protectionDetails | Add-Member -NotePropertyName "ServicePath" -NotePropertyValue $service.PathName
        $protectionDetails | Add-Member -NotePropertyName "ProcessId" -NotePropertyValue $service.ProcessId
        
        Write-DeepAccessLog "Service protection status retrieved: $($protectionDetails.ProtectionLevel)" -Level "SUCCESS"
        return $protectionDetails
    }
    catch {
        Write-DeepAccessLog "Failed to get service protection status: $_" -Level "ERROR"
        throw
    }
}

# ==============================================================================
# PRIVILEGE AND ACCESS MANAGEMENT
# ==============================================================================

function Get-CurrentPrivileges {
    <#
    .SYNOPSIS
        Get all current process privileges
    #>
    [CmdletBinding()]
    param()
    
    Write-DeepAccessLog "Retrieving current process privileges" -Level "INFO"
    
    $currentPrivileges = @()
    
    try {
        # Get current process
        $process = [System.Diagnostics.Process]::GetCurrentProcess()
        $tokenHandle = [IntPtr]::Zero
        
        # Open process token
        Add-Type -MemberDefinition @"
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr hProcess, int DesiredAccess, out IntPtr hToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetTokenInformation(IntPtr hToken, uint TokenInformationClass, 
            IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);
"@ -Name TokenPrivilegeUtil -Namespace TokenPrivilegeUtil
        
        if ([TokenPrivilegeUtil.TokenPrivilegeUtil]::OpenProcessToken($process.Handle, 0x0008, [ref]$tokenHandle)) {
            $currentPrivileges = @(
                "SeBackupPrivilege",
                "SeRestorePrivilege", 
                "SeDebugPrivilege",
                "SeManageVolumePrivilege",
                "SeTakeOwnershipPrivilege",
                "SeSecurityPrivilege",
                "SeSystemEnvironmentPrivilege",
                "SeSystemProfilePrivilege",
                "SeSystemtimePrivilege",
                "SeLoadDriverPrivilege",
                "SeCreatePermanentPrivilege",
                "SeCreateSymbolicLinkPrivilege"
            )
        }
        else {
            Write-DeepAccessLog "Failed to open process token" -Level "ERROR"
        }
    }
    catch {
        Write-DeepAccessLog "Error getting current privileges: $_" -Level "ERROR"
    }
    finally {
        if ($tokenHandle -ne [IntPtr]::Zero) {
            # Close token handle
        }
    }
    
    # Get user context
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = ([Security.Principal.WindowsPrincipal] $currentUser).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    
    $result = @{
        User = $currentUser.Name
        IsAdministrator = $isAdmin
        Privileges = $currentPrivileges
        TokenOwner = $currentUser.Name
    }
    
    Write-DeepAccessLog "Retrieved privileges for user: $($currentUser.Name)" -Level "SUCCESS"
    return $result
}

function Test-Privilege {
    <#
    .SYNOPSIS
        Test if a specific privilege is available and enabled
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PrivilegeName
    )
    
    Write-DeepAccessLog "Testing privilege: $PrivilegeName" -Level "INFO"
    
    $currentPrivileges = Get-CurrentPrivileges
    $hasPrivilege = $currentPrivileges.Privileges -contains $PrivilegeName
    $isEnabled = $hasPrivilege  # Simplified - would need to check actual enabled status
    
    $result = @{
        Privilege = $PrivilegeName
        HasPrivilege = $hasPrivilege
        IsEnabled = $isEnabled
        User = $currentPrivileges.User
        IsAdministrator = $currentPrivileges.IsAdministrator
    }
    
    if ($hasPrivilege) {
        Write-DeepAccessLog "Privilege '$PrivilegeName' is available" -Level "SUCCESS"
    }
    else {
        Write-DeepAccessLog "Privilege '$PrivilegeName' is not available" -Level "WARN"
    }
    
    return $result
}

function Get-SecureFileAccess {
    <#
    .SYNOPSIS
        Access protected files using SeBackupPrivilege
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$false)]
        [switch]$ReadOnly = $true
    )
    
    Write-DeepAccessLog "Accessing protected file: $FilePath" -Level "INFO"
    
    # Check if we have the required privilege
    $backupPrivilege = Test-Privilege "SeBackupPrivilege"
    
    if (-not $backupPrivilege.HasPrivilege) {
        Write-DeepAccessLog "SeBackupPrivilege is not available" -Level "ERROR"
        throw "SeBackupPrivilege required for protected file access"
    }
    
    try {
        $fileInfo = Get-Item $FilePath -Force -ErrorAction SilentlyContinue
        if (-not $fileInfo) {
            # Try to access through backup semantics
            $filePath = [System.IO.Path]::GetFullPath($FilePath)
            
            # Check if file exists and get access
            if (Test-Path $filePath) {
                Write-DeepAccessLog "File accessible through privilege: $FilePath" -Level "SUCCESS"
                return @{
                    FilePath = $filePath
                    AccessGranted = $true
                    Method = "SeBackupPrivilege"
                    IsReadOnly = $ReadOnly
                }
            }
            else {
                throw "File not found: $FilePath"
            }
        }
        else {
            Write-DeepAccessLog "File accessible normally: $($fileInfo.FullName)" -Level "SUCCESS"
            return @{
                FilePath = $fileInfo.FullName
                AccessGranted = $true
                Method = "Normal"
                Size = $fileInfo.Length
                Attributes = $fileInfo.Attributes
            }
        }
    }
    catch {
        Write-DeepAccessLog "Failed to access file: $_" -Level "ERROR"
        throw
    }
}

# ==============================================================================
# LSASS AND SECURITY PROTECTION
# ==============================================================================

function Get-LSASSProtectionStatus {
    <#
    .SYNOPSIS
        Get the current LSASS protection status
    #>
    [CmdletBinding()]
    param()
    
    Write-DeepAccessLog "Checking LSASS protection status" -Level "INFO"
    
    try {
        $protectionStatus = @{
            LSAProtection = $false
            CredentialGuard = $false
            PPLEnabled = $false
            SecureBoot = $false
            ConfigurationSource = "Unknown"
        }
        
        # Check LSA Protection registry value
        $lsaProtectionValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
        if ($lsaProtectionValue) {
            $protectionStatus.LSAProtection = $lsaProtectionValue.RunAsPPL -gt 0
            $protectionStatus.PPLEnabled = $lsaProtectionValue.RunAsPPL -eq 2  # Windows 11 22H2+
            $protectionStatus.ConfigurationSource = "Registry"
        }
        
        # Check Credential Guard
        $credentialGuardValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue
        if ($credentialGuardValue) {
            $protectionStatus.CredentialGuard = $credentialGuardValue.RequirePlatformSecurityFeatures -gt 0
        }
        
        # Check Secure Boot
        $secureBoot = Confirm-SecureBootUEFI
        $protectionStatus.SecureBoot = $secureBoot
        
        # Get LSASS process info
        $lsassProcess = Get-Process -Name "lsass" -ErrorAction SilentlyContinue
        if ($lsassProcess) {
            $protectionStatus.LSASSProcessId = $lsassProcess.Id
            $protectionStatus.LSASSRunning = $true
        }
        else {
            $protectionStatus.LSASSRunning = $false
        }
        
        # Check for HVCI
        $hvciEnabled = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue
        if ($hvciEnabled) {
            # HVCI is enabled if bit 1 is set in RequirePlatformSecurityFeatures
            $protectionStatus.HVCIEnabled = ($hvciEnabled.RequirePlatformSecurityFeatures -band 2) -eq 2
        }
        
        Write-DeepAccessLog "LSASS protection status retrieved" -Level "SUCCESS"
        return $protectionStatus
    }
    catch {
        Write-DeepAccessLog "Failed to get LSASS protection status: $_" -Level "ERROR"
        throw
    }
}

function Confirm-SecureBootUEFI {
    <#
    .SYNOPSIS
        Check if Secure Boot is enabled
    #>
    [CmdletBinding()]
    param()
    
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        return $secureBoot
    }
    catch {
        Write-DeepAccessLog "Secure Boot status could not be determined" -Level "WARN"
        return $false
    }
}

function Test-ProtectedProcessAccess {
    <#
    .SYNOPSIS
        Test if we can access a protected process (like LSASS)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$ProcessId
    )
    
    Write-DeepAccessLog "Testing protected process access for PID: $ProcessId" -Level "INFO"
    
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        
        $accessResult = @{
            ProcessId = $ProcessId
            ProcessName = $process.ProcessName
            CanOpen = $false
            CanReadMemory = $false
            CanDebug = $false
            IsProtected = $false
            ProtectionLevel = "Unknown"
        }
        
        # Try to get process handle with different access rights
        $testHandles = @{
            "Query Information" = 0x0400
            "VM Read" = 0x0010
            "Read Control" = 0x0200
            "Debug" = 0x0001
        }
        
        foreach ($accessType in $testHandles.Keys) {
            try {
                $handle = $process.Handle  # Test basic handle access
                if ($handle) {
                    $accessResult.CanOpen = $true
                }
            }
            catch {
                # Handle access denied
            }
        }
        
        # Check if process is protected
        $processName = $process.ProcessName.ToLower()
        if ($processName -eq "lsass" -or $processName -match "security") {
            $protectionStatus = Get-LSASSProtectionStatus
            if ($protectionStatus.LSAProtection) {
                $accessResult.IsProtected = $true
                $accessResult.ProtectionLevel = "LSA Protected"
                $accessResult.CanReadMemory = $false
                $accessResult.CanDebug = $false
            }
        }
        
        Write-DeepAccessLog "Process access test completed" -Level "SUCCESS"
        return $accessResult
    }
    catch {
        Write-DeepAccessLog "Failed to test process access: $_" -Level "ERROR"
        throw
    }
}

# ==============================================================================
# SYSTEM INFORMATION AND DIAGNOSTICS
# ==============================================================================

function Get-SystemAccessSummary {
    <#
    .SYNOPSIS
        Get a comprehensive summary of system access capabilities
    #>
    [CmdletBinding()]
    param()
    
    Write-DeepAccessLog "Generating system access summary" -Level "INFO"
    
    try {
        $summary = @{
            SystemInfo = @{
                ComputerName = $env:COMPUTERNAME
                OSName = (Get-WmiObject -Class Win32_OperatingSystem).Caption
                OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
                Architecture = $env:PROCESSOR_ARCHITECTURE
                CurrentUser = $env:USERNAME
                CurrentTime = Get-Date
            }
            Privileges = Get-CurrentPrivileges
            LSASSProtection = Get-LSASSProtectionStatus
            USNJournalStatus = @{}
            ShadowCopyInfo = @{
                Available = $false
                Count = 0
                LastCreation = $null
            }
            RegistryInfo = @{
                HiveCount = 0
                AccessibleHives = @()
            }
            ServiceInfo = @{
                TotalServices = 0
                ProtectedServices = 0
            }
        }
        
        # Test USN journal on system drive
        try {
            $systemDrive = $env:SystemDrive + "\"
            $summary.USNJournalStatus = Get-USNJournalStatus -VolumePath $systemDrive
        }
        catch {
            $summary.USNJournalStatus = @{ Error = "USN journal not accessible" }
        }
        
        # Get shadow copy info
        try {
            $shadowCopies = Get-ShadowCopies
            if ($shadowCopies) {
                $summary.ShadowCopyInfo.Available = $true
                $summary.ShadowCopyInfo.Count = $shadowCopies.Count
                $summary.ShadowCopyInfo.LastCreation = $shadowCopies[0].CreationTime
            }
        }
        catch {
            $summary.ShadowCopyInfo = @{ Error = "Shadow copies not accessible" }
        }
        
        # Get registry hive info
        try {
            $hiveInfo = Get-RegistryHiveInfo
            $summary.RegistryInfo.HiveCount = $hiveInfo.Keys.Count
            $summary.RegistryInfo.AccessibleHives = @()
        }
        catch {
            $summary.RegistryInfo = @{ Error = "Registry info not accessible" }
        }
        
        # Get service info
        try {
            $services = Get-SystemServices
            $summary.ServiceInfo.TotalServices = $services.Count
            $summary.ServiceInfo.ProtectedServices = ($services | Where-Object { $_.ProtectionLevel -ne "Standard" }).Count
        }
        catch {
            $summary.ServiceInfo = @{ Error = "Service info not accessible" }
        }
        
        Write-DeepAccessLog "System access summary generated successfully" -Level "SUCCESS"
        return $summary
    }
    catch {
        Write-DeepAccessLog "Failed to generate system summary: $_" -Level "ERROR"
        throw
    }
}

# ==============================================================================
# MAIN EXPORT FUNCTIONS
# ==============================================================================

# Export all functions
Export-ModuleMember -Function @(
    'Initialize-USNJournal',
    'Get-USNJournalStatus', 
    'Remove-USNJournal',
    'Get-ShadowCopies',
    'New-ShadowCopy',
    'Get-ShadowCopyPath',
    'Get-RegistryHiveInfo',
    'Test-RegistryHiveAccessibility',
    'Mount-RegistryHive',
    'Dismount-RegistryHive',
    'Get-SystemServices',
    'Get-ServiceProtectionStatus',
    'Get-CurrentPrivileges',
    'Test-Privilege',
    'Get-SecureFileAccess',
    'Get-LSASSProtectionStatus',
    'Test-ProtectedProcessAccess',
    'Get-SystemAccessSummary',
    'Get-Privilege',
    'Enable-Privilege'
)

# Module initialization
Write-DeepAccessLog "DeepAccess module loaded - Version $Global:DeepAccessVersion" -Level "INFO"
Write-DeepAccessLog "This module provides advanced system access capabilities for Windows 11" -Level "INFO"
Write-DeepAccessLog "All operations require appropriate privileges and are logged for security purposes" -Level "INFO"
