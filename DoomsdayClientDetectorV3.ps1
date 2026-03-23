#Requires -Version 5.1

function Show-Banner {
    Clear-Host

    $banner = @"
████████╗███████╗███████╗██╗      █████╗ ██████╗ ██████╗  ██████╗ 
╚══██╔══╝██╔════╝██╔════╝██║     ██╔══██╗██╔══██╗██╔══██╗██╔═══██╗
   ██║   █████╗  ███████╗██║     ███████║██████╔╝██████╔╝██║   ██║
   ██║   ██╔══╝  ╚════██║██║     ██╔══██║██╔═══╝ ██╔══██╗██║   ██║
   ██║   ███████╗███████║███████╗██║  ██║██║     ██║  ██║╚██████╔╝
   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ 
"@

    Write-Host $banner -ForegroundColor Red
    Write-Host ""
    Write-Host "                                  TESLAPRO SECURITY CONSOLE" -ForegroundColor White
    Write-Host "                            Doomsday Client Scanner v3 - USN Journal" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "                                  Author  : " -NoNewline -ForegroundColor DarkGray
    Write-Host "TeslaPro" -NoNewline -ForegroundColor White
    Write-Host "    Discord : " -NoNewline -ForegroundColor DarkGray
    Write-Host "@teamWSF" -ForegroundColor Yellow
    Write-Host ""
    Write-Host ("=" * 94) -ForegroundColor DarkGray
    Write-Host ""
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Global debug flag
$script:DebugMode = $false
$script:CheckUSN = $true

# Cache for USN journal data
$script:RecentDeletions = @{}
$script:USNSearched = $false

function Get-NTFSDrives {
    $ntfsDrives = @()
    
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }
    
    foreach ($drive in $drives) {
        try {
            $driveLetter = $drive.Root.Substring(0, 2)
            $volume = Get-Volume -DriveLetter $driveLetter[0] -ErrorAction SilentlyContinue
            
            if ($volume -and $volume.FileSystem -eq 'NTFS') {
                $ntfsDrives += $driveLetter[0]
            }
        }
        catch {
            continue
        }
    }
    
    return $ntfsDrives
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class NtdllDecompressor {
    [DllImport("ntdll.dll")]
    public static extern uint RtlDecompressBufferEx(
        ushort CompressionFormat,
        byte[] UncompressedBuffer,
        int UncompressedBufferSize,
        byte[] CompressedBuffer,
        int CompressedBufferSize,
        out int FinalUncompressedSize,
        IntPtr WorkSpace
    );
    
    [DllImport("ntdll.dll")]
    public static extern uint RtlGetCompressionWorkSpaceSize(
        ushort CompressionFormat,
        out uint CompressBufferWorkSpaceSize,
        out uint CompressFragmentWorkSpaceSize
    );
    
    public static byte[] Decompress(byte[] compressed) {
        if (compressed.Length < 8) return null;
        if (compressed[0] != 0x4D || compressed[1] != 0x41 || compressed[2] != 0x4D) {
            return null;
        }
        
        int uncompSize = BitConverter.ToInt32(compressed, 4);
        
        uint wsComp, wsFrag;
        if (RtlGetCompressionWorkSpaceSize(4, out wsComp, out wsFrag) != 0) return null;
        
        IntPtr workspace = Marshal.AllocHGlobal((int)wsFrag);
        byte[] result = new byte[uncompSize];
        
        try {
            int finalSize;
            byte[] compData = new byte[compressed.Length - 8];
            Array.Copy(compressed, 8, compData, 0, compData.Length);
            
            uint status = RtlDecompressBufferEx(4, result, uncompSize, 
                compData, compData.Length, out finalSize, workspace);
            
            if (status != 0) return null;
            return result;
        }
        finally {
            Marshal.FreeHGlobal(workspace);
        }
    }
}
"@

function Get-RecentDeletionsFromUSN {
    param(
        [string[]]$DriveLetters,
        [int]$MinutesBack = 30
    )
    
    if ($script:USNSearched) {
        return $script:RecentDeletions
    }
    
    $allRecentActivity = @{}
    
    foreach ($driveLetter in $DriveLetters) {
        try {
            if ($script:DebugMode) {
                Write-Host "[DEBUG] Reading USN Journal on drive $driveLetter`: (last $MinutesBack minutes)" -ForegroundColor DarkGray
            }
            
            $cutoffTime = (Get-Date).AddMinutes(-$MinutesBack)
            $usnOutput = & fsutil usn readjournal "$driveLetter`:" 2>$null
            
            if ($LASTEXITCODE -ne 0) {
                if ($script:DebugMode) {
                    Write-Host "[DEBUG] Unable to read USN Journal on drive $driveLetter`: (may be disabled)" -ForegroundColor DarkGray
                }
                continue
            }
            
            $totalLines = $usnOutput.Count
            
            if ($totalLines -eq 0) {
                if ($script:DebugMode) {
                    Write-Host "[DEBUG] No USN Journal data on drive $driveLetter`:" -ForegroundColor DarkGray
                }
                continue
            }
            
            $recentActivity = @{}
            $activityCount = 0
            $currentFile = ""
            $currentTime = $null
            $currentReason = ""
            $entriesProcessed = 0
            
            foreach ($line in $usnOutput) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                
                if ($line -match 'File name\s+:\s*(.+)$') {
                    $currentFile = $Matches[1].Trim()
                }
                elseif ($line -match 'Time stamp\s+:\s*(.+)$') {
                    $timeStr = $Matches[1].Trim()
                    try {
                        $currentTime = [DateTime]::Parse($timeStr)
                    } catch {
                        $currentTime = $null
                    }
                }
                elseif ($line -match 'Reason\s+:\s*(.+)$') {
                    $entriesProcessed++
                    $currentReason = $Matches[1].Trim()
                    
                    if ($currentFile -and $currentTime -and $currentTime -gt $cutoffTime) {
                        $fullKey = "$driveLetter`:\$currentFile"
                        
                        if (-not $recentActivity.ContainsKey($fullKey) -or 
                            $recentActivity[$fullKey].Timestamp -lt $currentTime) {
                            
                            $recentActivity[$fullKey] = @{
                                Timestamp = $currentTime
                                Reason = $currentReason
                                Drive = $driveLetter
                            }
                            
                            $activityCount++
                        }
                    }
                    
                    $currentFile = ""
                    $currentTime = $null
                    $currentReason = ""
                }
            }
            
            if ($script:DebugMode) {
                Write-Host "[DEBUG] Drive $driveLetter`: found $activityCount files with recent activity" -ForegroundColor DarkGray
            }
            
            foreach ($key in $recentActivity.Keys) {
                $allRecentActivity[$key] = $recentActivity[$key]
            }
            
        }
        catch {
            if ($script:DebugMode) {
                Write-Host "[DEBUG] Error reading USN Journal on drive $driveLetter`: - $_" -ForegroundColor DarkGray
            }
            continue
        }
    }
    
    $script:RecentDeletions = $allRecentActivity
    $script:USNSearched = $true
    
    if ($script:DebugMode) {
        Write-Host ""
        Write-Host "[DEBUG] Total unique files with recent activity across all drives: $($allRecentActivity.Count)" -ForegroundColor DarkGray
        Write-Host ""
    }
    
    return $allRecentActivity
}

function Test-RecentlyDeleted {
    param(
        [string]$FilePath
    )
    
    if ($script:RecentDeletions.ContainsKey($FilePath)) {
        return $script:RecentDeletions[$FilePath]
    }
    
    $fileName = [System.IO.Path]::GetFileName($FilePath)
    
    foreach ($key in $script:RecentDeletions.Keys) {
        if ($key -like "*\$fileName") {
            return $script:RecentDeletions[$key]
        }
    }
    
    return $null
}

function Get-PrefetchVersion {
    param([byte[]]$data)
    
    if ($data.Length -lt 8) { return 0 }
    
    $sig = [System.Text.Encoding]::ASCII.GetString($data, 4, 4)
    if ($sig -ne "SCCA") { return 0 }
    
    $version = [BitConverter]::ToUInt32($data, 0)
    return $version
}

function Get-SystemIndexes {
    param([string]$FilePath)
    
    try {
        $data = [System.IO.File]::ReadAllBytes($FilePath)
        
        if ($script:DebugMode) {
            Write-Host "  [DEBUG] File: $([System.IO.Path]::GetFileName($FilePath))" -ForegroundColor Magenta
            Write-Host "  [DEBUG] Raw size: $($data.Length) bytes" -ForegroundColor Magenta
        }
        
        $isCompressed = ($data[0] -eq 0x4D -and $data[1] -eq 0x41 -and $data[2] -eq 0x4D)
        
        if ($script:DebugMode) {
            Write-Host "  [DEBUG] Compressed: $isCompressed" -ForegroundColor Magenta
        }
        
        if ($isCompressed) {
            $data = [NtdllDecompressor]::Decompress($data)
            if ($data -eq $null) {
                Write-Warning "Failed to decompress: $FilePath"
                return @()
            }
            
            if ($script:DebugMode) {
                Write-Host "  [DEBUG] Decompressed size: $($data.Length) bytes" -ForegroundColor Magenta
            }
        }
        
        if ($data.Length -lt 108) {
            Write-Warning "File too small after decompression: $FilePath"
            return @()
        }
        
        $version = Get-PrefetchVersion -data $data
        
        if ($script:DebugMode) {
            Write-Host "  [DEBUG] Prefetch version: $version" -ForegroundColor Magenta
        }
        
        $sig = [System.Text.Encoding]::ASCII.GetString($data, 4, 4)
        if ($sig -ne "SCCA") {
            Write-Warning "Invalid file signature: $FilePath (got: $sig)"
            return @()
        }
        
        $stringsOffset = 0
        $stringsSize = 0
        
        switch ($version) {
            17 {
                $stringsOffset = [BitConverter]::ToUInt32($data, 100)
                $stringsSize = [BitConverter]::ToUInt32($data, 104)
            }
            23 {
                $stringsOffset = [BitConverter]::ToUInt32($data, 100)
                $stringsSize = [BitConverter]::ToUInt32($data, 104)
            }
            26 {
                $stringsOffset = [BitConverter]::ToUInt32($data, 100)
                $stringsSize = [BitConverter]::ToUInt32($data, 104)
            }
            30 {
                $stringsOffset = [BitConverter]::ToUInt32($data, 100)
                $stringsSize = [BitConverter]::ToUInt32($data, 104)
            }
            31 {
                $stringsOffset = [BitConverter]::ToUInt32($data, 100)
                $stringsSize = [BitConverter]::ToUInt32($data, 104)
            }
            default {
                Write-Warning "Unknown prefetch version $version for: $FilePath"
                $stringsOffset = [BitConverter]::ToUInt32($data, 100)
                $stringsSize = [BitConverter]::ToUInt32($data, 104)
            }
        }
        
        if ($script:DebugMode) {
            Write-Host "  [DEBUG] Strings offset: $stringsOffset" -ForegroundColor Magenta
            Write-Host "  [DEBUG] Strings size: $stringsSize" -ForegroundColor Magenta
        }
        
        if ($stringsOffset -eq 0 -or $stringsSize -eq 0) {
            Write-Warning "Invalid string section offsets: $FilePath"
            return @()
        }
        
        if ($stringsOffset -ge $data.Length -or ($stringsOffset + $stringsSize) -gt $data.Length) {
            Write-Warning "String section out of bounds: $FilePath (offset: $stringsOffset, size: $stringsSize, data: $($data.Length))"
            return @()
        }
        
        $filenames = @()
        $pos = $stringsOffset
        $endPos = $stringsOffset + $stringsSize
        
        while ($pos -lt $endPos -and $pos -lt $data.Length - 2) {
            $nullPos = $pos
            while ($nullPos -lt $data.Length - 1) {
                if ($data[$nullPos] -eq 0 -and $data[$nullPos + 1] -eq 0) {
                    break
                }
                $nullPos += 2
            }
            
            if ($nullPos -gt $pos) {
                $strLen = $nullPos - $pos
                if ($strLen -gt 0 -and $strLen -lt 2048) {
                    try {
                        $filename = [System.Text.Encoding]::Unicode.GetString($data, $pos, $strLen)
                        if ($filename.Length -gt 0) {
                            $filenames += $filename
                        }
                    }
                    catch { }
                }
            }
            
            $pos = $nullPos + 2
            
            if ($filenames.Count -gt 1000) { break }
        }
        
        if ($script:DebugMode) {
            Write-Host "  [DEBUG] Extracted $($filenames.Count) filenames" -ForegroundColor Magenta
        }
        
        return $filenames
    }
    catch {
        Write-Warning "Error parsing $FilePath : $_"
        if ($script:DebugMode) {
            Write-Host "  [DEBUG] Exception: $($_.Exception.GetType().Name)" -ForegroundColor Red
            Write-Host "  [DEBUG] Message: $($_.Exception.Message)" -ForegroundColor Red
        }
        return @()
    }
}

function Test-FileInSizeRange {
    param(
        [string]$Path,
        [long]$MinBytes = 200KB,
        [long]$MaxBytes = 15MB
    )
    
    if (-not (Test-Path $Path -PathType Leaf)) {
        return $false
    }
    
    try {
        $size = (Get-Item $Path -ErrorAction Stop).Length
        return ($size -ge $MinBytes -and $size -le $MaxBytes)
    }
    catch {
        return $false
    }
}

$script:BytePatterns = @(
    @{
        Name = "Pattern #1"
        Bytes = "6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A160C14005C6588B800"
    },
    @{
        Name = "Pattern #2"
        Bytes = "0C1504851D85160A6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A16"
    },
    @{
        Name = "Pattern #3"
        Bytes = "5910071088544C2A2BB8004D3B033DA7000A2B1C03548402011C1008A1FFF61A9E000C1A110800A2000503AC04AC00000000000A0005004E000101FA000001D3"
    }
)

$script:ClassPatterns = @(
    "net/java/f",
    "net/java/g",
    "net/java/h",
    "net/java/i",
    "net/java/k",
    "net/java/l",
    "net/java/m",
    "net/java/r",
    "net/java/s",
    "net/java/t",
    "net/java/y"
)

function ConvertHex-ToBytes {
    param([string]$hexString)
    
    $bytes = New-Object byte[] ($hexString.Length / 2)
    for ($i = 0; $i -lt $hexString.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($hexString.Substring($i, 2), 16)
    }
    return $bytes
}

function Search-BytePattern {
    param(
        [byte[]]$data,
        [byte[]]$pattern
    )
    
    $patternLength = $pattern.Length
    $dataLength = $data.Length
    
    for ($i = 0; $i -le ($dataLength - $patternLength); $i++) {
        $match = $true
        for ($j = 0; $j -lt $patternLength; $j++) {
            if ($data[$i + $j] -ne $pattern[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            return $true
        }
    }
    return $false
}

function Search-ClassPattern {
    param(
        [byte[]]$data,
        [string]$className
    )
    
    $classBytes = [System.Text.Encoding]::ASCII.GetBytes($className)
    return Search-BytePattern -data $data -pattern $classBytes
}

function Test-ZipMagicBytes {
    param([string]$Path)
    
    try {
        $fileStream = [System.IO.File]::OpenRead($Path)
        $reader = New-Object System.IO.BinaryReader($fileStream)
        
        if ($fileStream.Length -lt 2) {
            $reader.Close()
            $fileStream.Close()
            return $false
        }
        
        $byte1 = $reader.ReadByte()
        $byte2 = $reader.ReadByte()
        
        $reader.Close()
        $fileStream.Close()
        
        return ($byte1 -eq 0x50 -and $byte2 -eq 0x4B)
        
    } catch {
        return $false
    }
}

function Find-SingleLetterClasses {
    param([string]$Path)
    
    $singleLetterClasses = @()
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        
        $jar = [System.IO.Compression.ZipFile]::OpenRead($Path)
        
        foreach ($entry in $jar.Entries) {
            if ($entry.FullName -like "*.class") {
                $className = $entry.FullName
                $parts = $className -split '/'
                $filename = $parts[-1]
                $classNameOnly = $filename -replace '\.class$', ''
                
                if ($classNameOnly -match '^[a-zA-Z]$') {
                    $fullPath = ($parts[0..($parts.Length-2)] -join '/') + '/' + $classNameOnly
                    $singleLetterClasses += $fullPath
                }
            }
        }
        
        $jar.Dispose()
        
    } catch {
    }
    
    return $singleLetterClasses
}

function Test-DoomsdayClient {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    $result = [PSCustomObject]@{
        IsDetected = $false
        Confidence = "NONE"
        BytePatternMatches = @()
        ClassNameMatches = @()
        SingleLetterClasses = @()
        IsRenamedJar = $false
        Error = $null
    }
    
    if (-not (Test-Path $Path -PathType Leaf)) {
        $result.Error = "File not found"
        return $result
    }
    
    try {
        $fileExtension = [System.IO.Path]::GetExtension($Path).ToLower()
        $hasPKHeader = Test-ZipMagicBytes -Path $Path
        
        if ($hasPKHeader -and $fileExtension -ne ".jar") {
            $result.IsRenamedJar = $true
            $result.IsDetected = $true
            $result.Confidence = "HIGH"
        }
        
        if (-not $hasPKHeader) {
            $result.Error = "File is not a JAR/ZIP file (missing PK header)"
            return $result
        }
        
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $jar = [System.IO.Compression.ZipFile]::OpenRead($Path)
        
        $classFiles = $jar.Entries | Where-Object { $_.FullName -like "*.class" }
        $classCount = $classFiles.Count
        
        if ($classCount -gt 30) {
            $jar.Dispose()
            $result.Error = "Skipped: Too many classes ($classCount) - likely legitimate library"
            return $result
        }
        
        if ($classCount -eq 0) {
            $jar.Dispose()
            $result.Error = "No .class files found in JAR"
            return $result
        }
        
        $allBytes = @()
        
        foreach ($entry in $classFiles) {
            $stream = $entry.Open()
            $reader = New-Object System.IO.BinaryReader($stream)
            $bytes = $reader.ReadBytes([int]$entry.Length)
            $allBytes += $bytes
            $reader.Close()
            $stream.Close()
        }
        
        $jar.Dispose()
        
        foreach ($pattern in $script:BytePatterns) {
            $patternBytes = ConvertHex-ToBytes -hexString $pattern.Bytes
            
            if (Search-BytePattern -data $allBytes -pattern $patternBytes) {
                $result.BytePatternMatches += $pattern.Name
            }
        }
        
        foreach ($className in $script:ClassPatterns) {
            if (Search-ClassPattern -data $allBytes -className $className) {
                $result.ClassNameMatches += $className
            }
        }
        
        $result.SingleLetterClasses = Find-SingleLetterClasses -Path $Path
        
        $byteMatchCount = $result.BytePatternMatches.Count
        $classMatchCount = $result.ClassNameMatches.Count
        $singleLetterCount = $result.SingleLetterClasses.Count
        
        if ($byteMatchCount -ge 2) {
            $result.IsDetected = $true
            $result.Confidence = "HIGH"
        }
        elseif ($byteMatchCount -eq 1 -and ($classMatchCount -ge 5 -or $singleLetterCount -ge 5)) {
            $result.IsDetected = $true
            $result.Confidence = "MEDIUM"
        }
        elseif ($byteMatchCount -eq 1) {
            $result.IsDetected = $true
            $result.Confidence = "LOW"
        }
        elseif ($singleLetterCount -ge 8 -and $classMatchCount -ge 3) {
            $result.IsDetected = $true
            $result.Confidence = "MEDIUM"
        }
        elseif ($singleLetterCount -ge 5 -or $classMatchCount -ge 5) {
            $result.IsDetected = $true
            $result.Confidence = "LOW"
        }
        
        if ($result.IsRenamedJar -and $result.Confidence -eq "NONE") {
            $result.Confidence = "MEDIUM"
        }
        
    } catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

function Test-SelfDestructSuspicion {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [string]$SourceFile = "",

        $RecentDeletion = $null
    )

    $result = [PSCustomObject]@{
        IsSuspicious = $false
        Confidence = "NONE"
        Score = 0
        Reasons = @()
        FileName = [System.IO.Path]::GetFileName($Path)
        Extension = [System.IO.Path]::GetExtension($Path).ToLower()
        Path = $Path
    }

    $lowerPath = $Path.ToLower()
    $fileName = [System.IO.Path]::GetFileName($Path)
    $lowerName = $fileName.ToLower()

    if ($result.Extension -in @(".jar", ".exe", ".dll")) {
        $result.Score += 2
        $result.Reasons += "Java-referenced executable/container extension"
    }

    if ($result.Extension -ne ".jar" -and $result.Extension -in @(".exe", ".bin", ".dat", ".tmp", ".dll")) {
        $result.Score += 2
        $result.Reasons += "Non-JAR extension often used for renamed JAR payloads"
    }

    $keywordHits = @(
        "doom", "doomsday", "client", "ghost", "inject", "loader", "launch", "minecraft",
        "mc", "cheat", "hack", "clicker", "autoclick", "bypass", "destruct", "selfdestruct"
    ) | Where-Object { $lowerName -like "*$_*" }

    if ($keywordHits.Count -gt 0) {
        $result.Score += [Math]::Min(4, $keywordHits.Count + 1)
        $result.Reasons += "Suspicious filename keywords: $($keywordHits -join ', ')"
    }

    if ($lowerPath -match '\\downloads\\|\\desktop\\|\\documents\\|\\appdata\\roaming\\|\\appdata\\local\\|\\temp\\|\\tmp\\|\\minecraft\\|\\mods\\|\\versions\\|\\libraries\\') {
        $result.Score += 2
        $result.Reasons += "Stored in a user/mod/temp-related path"
    }

    if ($SourceFile -match '^JAVA.*\.pf$') {
        $result.Score += 2
        $result.Reasons += "Referenced by Java prefetch"
    }

    if ($RecentDeletion) {
        $result.Score += 3
        $result.Reasons += "Recently removed or modified according to USN Journal"

        if ($RecentDeletion.Reason) {
            if ($RecentDeletion.Reason -match 'FILE_DELETE|CLOSE|RENAME|DATA_TRUNCATION') {
                $result.Score += 2
                $result.Reasons += "USN reason suggests deletion/rename/truncation"
            }
        }
    }

    if ($lowerName -match '^[a-z0-9_\-]{4,}\.(jar|exe|dll|bin|dat)$') {
        $result.Score += 1
        $result.Reasons += "Generic/randomized payload-style filename"
    }

    if (($lowerPath -match '\\minecraft\\|\\mods\\|\\versions\\|\\libraries\\|\\appdata\\roaming\\') -and
        ($result.Extension -in @(".jar", ".exe"))) {
        $result.Score += 3
        $result.Reasons += "Missing Java artifact from a highly suspicious Minecraft/client path"
    }

    if ($result.Score -ge 10) {
        $result.IsSuspicious = $true
        $result.Confidence = "HIGH"
    }
    elseif ($result.Score -ge 7) {
        $result.IsSuspicious = $true
        $result.Confidence = "MEDIUM"
    }
    elseif ($result.Score -ge 4) {
        $result.IsSuspicious = $true
        $result.Confidence = "LOW"
    }

    return $result
}

function Write-TeslaSeparator {
    Write-Host ("=" * 94) -ForegroundColor DarkGray
}

function Write-TeslaSubSeparator {
    Write-Host ("-" * 94) -ForegroundColor DarkGray
}

function Write-TeslaHeader {
    param(
        [string]$Title,
        [string]$Subtitle = ""
    )

    Clear-Host
    Write-Host "████████╗███████╗███████╗██╗      █████╗ ██████╗ ██████╗  ██████╗ " -ForegroundColor Red
    Write-Host "╚══██╔══╝██╔════╝██╔════╝██║     ██╔══██╗██╔══██╗██╔══██╗██╔═══██╗" -ForegroundColor Red
    Write-Host "   ██║   █████╗  ███████╗██║     ███████║██████╔╝██████╔╝██║   ██║" -ForegroundColor Red
    Write-Host "   ██║   ██╔══╝  ╚════██║██║     ██╔══██║██╔═══╝ ██╔══██╗██║   ██║" -ForegroundColor Red
    Write-Host "   ██║   ███████╗███████║███████╗██║  ██║██║     ██║  ██║╚██████╔╝" -ForegroundColor Red
    Write-Host "   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ " -ForegroundColor Red
    Write-Host ""
    Write-Host "                                  TESLAPRO SECURITY CONSOLE" -ForegroundColor White
    if ($Subtitle) {
        Write-Host "                                  $Subtitle" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-TeslaSeparator
    Write-Host ("  " + $Title) -ForegroundColor Cyan
    Write-TeslaSeparator
    Write-Host ""
}

function Write-TeslaStat {
    param(
        [string]$Label,
        [string]$Value,
        [ConsoleColor]$ValueColor = [ConsoleColor]::White
    )

    $paddedLabel = $Label.PadRight(22)
    Write-Host "  $paddedLabel : " -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -ForegroundColor $ValueColor
}

function Read-TeslaChoice {
    Write-Host ""
    Write-Host "  [1] Summary    [2] Detections    [3] Deleted Files    [4] Self-Destruct    [Q] Exit" -ForegroundColor Cyan
    Write-TeslaSeparator
    Write-Host ""
    Write-Host "  Select option: " -NoNewline -ForegroundColor White
    return (Read-Host).Trim().ToUpper()
}

function Show-TeslaSummaryTab {
    param(
        [hashtable]$Stats,
        [array]$Detections,
        [array]$DeletedFiles
    )

    Write-TeslaHeader -Title "SCAN SUMMARY" -Subtitle "Forensic Overview"

    $high = ($Detections | Where-Object { $_.Confidence -eq "HIGH" }).Count
    $medium = ($Detections | Where-Object { $_.Confidence -eq "MEDIUM" }).Count
    $low = ($Detections | Where-Object { $_.Confidence -eq "LOW" }).Count
    $selfDestructCount = ($DeletedFiles | Where-Object { $_.Suspicious }).Count

    if ($Detections.Count -gt 0) {
        Write-TeslaStat -Label "Scan Status" -Value "THREATS FOUND" -ValueColor Red
    } else {
        Write-TeslaStat -Label "Scan Status" -Value "CLEAN" -ValueColor Green
    }

    Write-TeslaStat -Label "Scanner Owner" -Value "TeslaPro" -ValueColor White
    Write-TeslaStat -Label "Discord" -Value "@teamWSF" -ValueColor Yellow
    Write-TeslaStat -Label "Windows Version" -Value $Stats.WindowsVersion -ValueColor White
    Write-TeslaStat -Label "Java Prefetch Files" -Value "$($Stats.JavaPrefetchCount)" -ValueColor White
    Write-TeslaStat -Label "Parsed Prefetch Files" -Value "$($Stats.SuccessfulParsing) / $($Stats.ProcessedFiles)" -ValueColor White
    Write-TeslaStat -Label "Extracted Paths" -Value "$($Stats.TotalIndexes)" -ValueColor White
    Write-TeslaStat -Label "Unique Paths" -Value "$($Stats.UniquePaths)" -ValueColor White
    Write-TeslaStat -Label "Existing Files" -Value "$($Stats.ExistingFiles)" -ValueColor White
    Write-TeslaStat -Label "Files Scanned" -Value "$($Stats.FilesScanned)" -ValueColor White
    Write-TeslaStat -Label "Files Skipped" -Value "$($Stats.FilesSkipped)" -ValueColor White

    if ($Stats.MissingFiles -gt 0) {
        Write-TeslaStat -Label "Missing Files" -Value "$($Stats.MissingFiles)" -ValueColor Yellow
    } else {
        Write-TeslaStat -Label "Missing Files" -Value "$($Stats.MissingFiles)" -ValueColor Green
    }

    if ($DeletedFiles.Count -gt 0) {
        Write-TeslaStat -Label "Deleted Entries" -Value "$($DeletedFiles.Count)" -ValueColor Yellow
    } else {
        Write-TeslaStat -Label "Deleted Entries" -Value "0" -ValueColor Green
    }

    if ($Detections.Count -gt 0) {
        Write-TeslaStat -Label "Detections" -Value "$($Detections.Count)" -ValueColor Red
    } else {
        Write-TeslaStat -Label "Detections" -Value "0" -ValueColor Green
    }

    if ($selfDestructCount -gt 0) {
        Write-TeslaStat -Label "Self-Destruct Hits" -Value "$selfDestructCount" -ValueColor Red
    } else {
        Write-TeslaStat -Label "Self-Destruct Hits" -Value "0" -ValueColor Green
    }

    Write-Host ""
    Write-TeslaSubSeparator
    Write-Host "  CONFIDENCE BREAKDOWN" -ForegroundColor White
    Write-TeslaSubSeparator
    Write-Host ""

    if ($high -gt 0) {
        Write-TeslaStat -Label "HIGH" -Value "$high" -ValueColor Red
    } else {
        Write-TeslaStat -Label "HIGH" -Value "0" -ValueColor Green
    }

    if ($medium -gt 0) {
        Write-TeslaStat -Label "MEDIUM" -Value "$medium" -ValueColor Yellow
    } else {
        Write-TeslaStat -Label "MEDIUM" -Value "0" -ValueColor Green
    }

    if ($low -gt 0) {
        Write-TeslaStat -Label "LOW" -Value "$low" -ValueColor Gray
    } else {
        Write-TeslaStat -Label "LOW" -Value "0" -ValueColor Green
    }
}

function Show-TeslaDetectionsTab {
    param([array]$Detections)

    Write-TeslaHeader -Title "DETECTION DETAILS" -Subtitle "Threat View"

    if ($Detections.Count -eq 0) {
        Write-Host "  No Doomsday Client detections were found on this system." -ForegroundColor Green
        Write-Host ""
        return
    }

    $i = 1
    foreach ($detection in $Detections) {
        Write-Host "  [$i] " -NoNewline -ForegroundColor Red
        Write-Host $detection.Path -ForegroundColor White
        Write-Host ""

        Write-TeslaStat -Label "Source File" -Value $detection.SourceFile -ValueColor Cyan
        Write-TeslaStat -Label "Index Number" -Value "#$($detection.IndexNumber)" -ValueColor White

        switch ($detection.Confidence) {
            "HIGH"   { Write-TeslaStat -Label "Confidence" -Value "HIGH" -ValueColor Red }
            "MEDIUM" { Write-TeslaStat -Label "Confidence" -Value "MEDIUM" -ValueColor Yellow }
            "LOW"    { Write-TeslaStat -Label "Confidence" -Value "LOW" -ValueColor Gray }
            default  { Write-TeslaStat -Label "Confidence" -Value $detection.Confidence -ValueColor White }
        }

        if ($detection.IsRenamedJar) {
            Write-TeslaStat -Label "Renamed JAR" -Value "YES" -ValueColor Red
        } else {
            Write-TeslaStat -Label "Renamed JAR" -Value "NO" -ValueColor Green
        }

        Write-TeslaStat -Label "Byte Patterns" -Value "$($detection.BytePatterns)" -ValueColor White
        Write-TeslaStat -Label "Class Matches" -Value "$($detection.ClassMatches)" -ValueColor White
        Write-TeslaStat -Label "Single-Letter Classes" -Value "$($detection.SingleLetterClasses)" -ValueColor White

        Write-Host ""
        Write-TeslaSubSeparator
        $i++
    }
}

function Show-TeslaDeletedFilesTab {
    param([array]$DeletedFiles)

    Write-TeslaHeader -Title "DELETED / MISSING FILES" -Subtitle "File Activity View"

    if ($DeletedFiles.Count -eq 0) {
        Write-Host "  No suspicious deleted or missing JAR/EXE/DLL files were recorded." -ForegroundColor Green
        Write-Host ""
        return
    }

    $i = 1
    foreach ($file in $DeletedFiles) {
        Write-Host "  [$i] " -NoNewline -ForegroundColor Yellow
        Write-Host $file.Path -ForegroundColor White
        Write-Host ""

        Write-TeslaStat -Label "Source Prefetch" -Value $file.SourceFile -ValueColor Cyan

        if ($file.DeletionTime) {
            Write-TeslaStat -Label "Last Activity" -Value $file.DeletionTime -ValueColor White
        } else {
            Write-TeslaStat -Label "Last Activity" -Value "Unknown" -ValueColor Gray
        }

        if ($file.Reason) {
            Write-TeslaStat -Label "USN Reason" -Value $file.Reason -ValueColor White
        } else {
            Write-TeslaStat -Label "USN Reason" -Value "Unavailable" -ValueColor Gray
        }

        if ($file.Suspicious) {
            switch ($file.SuspicionConfidence) {
                "HIGH"   { Write-TeslaStat -Label "Self-Destruct" -Value "HIGH" -ValueColor Red }
                "MEDIUM" { Write-TeslaStat -Label "Self-Destruct" -Value "MEDIUM" -ValueColor Yellow }
                "LOW"    { Write-TeslaStat -Label "Self-Destruct" -Value "LOW" -ValueColor Gray }
                default  { Write-TeslaStat -Label "Self-Destruct" -Value $file.SuspicionConfidence -ValueColor White }
            }
            Write-TeslaStat -Label "Suspicion Score" -Value "$($file.SuspicionScore)" -ValueColor White
        } else {
            Write-TeslaStat -Label "Self-Destruct" -Value "NO" -ValueColor Green
        }

        Write-Host ""
        Write-TeslaSubSeparator
        $i++
    }
}

function Show-TeslaSelfDestructTab {
    param([array]$Findings)

    Write-TeslaHeader -Title "SELF-DESTRUCT ANALYSIS" -Subtitle "Forensic Suspicion View"

    if ($Findings.Count -eq 0) {
        Write-Host "  No likely self-destructed Java client artifacts were identified." -ForegroundColor Green
        Write-Host ""
        return
    }

    $i = 1
    foreach ($item in $Findings) {
        Write-Host "  [$i] " -NoNewline -ForegroundColor Red
        Write-Host $item.Path -ForegroundColor White
        Write-Host ""

        Write-TeslaStat -Label "Source Prefetch" -Value $item.SourceFile -ValueColor Cyan

        switch ($item.Confidence) {
            "HIGH"   { Write-TeslaStat -Label "Confidence" -Value "HIGH" -ValueColor Red }
            "MEDIUM" { Write-TeslaStat -Label "Confidence" -Value "MEDIUM" -ValueColor Yellow }
            "LOW"    { Write-TeslaStat -Label "Confidence" -Value "LOW" -ValueColor Gray }
            default  { Write-TeslaStat -Label "Confidence" -Value $item.Confidence -ValueColor White }
        }

        Write-TeslaStat -Label "Suspicion Score" -Value "$($item.Score)" -ValueColor White

        if ($item.DeletionTime) {
            Write-TeslaStat -Label "Last Activity" -Value $item.DeletionTime -ValueColor White
        }
        else {
            Write-TeslaStat -Label "Last Activity" -Value "Unknown" -ValueColor Gray
        }

        if ($item.Reason) {
            Write-TeslaStat -Label "USN Reason" -Value $item.Reason -ValueColor White
        }
        else {
            Write-TeslaStat -Label "USN Reason" -Value "Unavailable" -ValueColor Gray
        }

        if ($item.Reasons -and $item.Reasons.Count -gt 0) {
            Write-Host ""
            Write-Host "  Indicators:" -ForegroundColor White
            foreach ($r in $item.Reasons) {
                Write-Host "    - $r" -ForegroundColor DarkGray
            }
        }

        Write-Host ""
        Write-TeslaSubSeparator
        $i++
    }
}

function Show-TeslaDashboard {
    param(
        [hashtable]$Stats,
        [array]$Detections,
        [array]$DeletedFiles,
        [array]$SelfDestructFindings
    )

    $currentTab = "1"

    while ($true) {
        switch ($currentTab) {
            "1" { Show-TeslaSummaryTab -Stats $Stats -Detections $Detections -DeletedFiles $DeletedFiles }
            "2" { Show-TeslaDetectionsTab -Detections $Detections }
            "3" { Show-TeslaDeletedFilesTab -DeletedFiles $DeletedFiles }
            "4" { Show-TeslaSelfDestructTab -Findings $SelfDestructFindings }
            default { Show-TeslaSummaryTab -Stats $Stats -Detections $Detections -DeletedFiles $DeletedFiles }
        }

        $choice = Read-TeslaChoice

        switch ($choice) {
            "1" { $currentTab = "1" }
            "2" { $currentTab = "2" }
            "3" { $currentTab = "3" }
            "4" { $currentTab = "4" }
            "Q" { break }
            default { }
        }
    }
}

function Start-DoomsdayScan {
    param(
        [switch]$Debug
    )
    
    $script:DebugMode = $Debug
    
    Show-Banner
    
    if (-not (Test-Administrator)) {
        Write-Host ""
        Write-Host "ERROR: " -ForegroundColor Red -NoNewline
        Write-Host "Administrator privileges required!"
        Write-Host ""
        Write-Host "Please launch CMD or PowerShell as admin!" -ForegroundColor Yellow
        Write-Host ""
        return
    }
    
    $osVersion = [System.Environment]::OSVersion.Version
    Write-Host "[*] Windows Version: $($osVersion.Major).$($osVersion.Minor) Build $($osVersion.Build)" -ForegroundColor Cyan
    
    if ($osVersion.Major -eq 10) {
        if ($osVersion.Build -ge 22000) {
            Write-Host "[*] Detected: Windows 11" -ForegroundColor Green
        } else {
            Write-Host "[*] Detected: Windows 10" -ForegroundColor Green
        }
    }
    Write-Host ""
    
    Write-Host "[*] Extracting file indexes..." -ForegroundColor Cyan
    Write-Host ""
    
    $systemPath = "C:\Windows\" + "Pre" + "fetch"
    
    if (-not (Test-Path $systemPath)) {
        Write-Host "[!] Prefetch directory not found: $systemPath" -ForegroundColor Red
        return
    }
    
    $javaFiles = Get-ChildItem -Path $systemPath -Filter "JAVA*.EXE-*.pf" -ErrorAction SilentlyContinue
    
    if ($javaFiles.Count -eq 0) {
        Write-Host "[!] No JAVA prefetch files found in $systemPath" -ForegroundColor Yellow
        Write-Host "[*] This could mean:" -ForegroundColor Yellow
        Write-Host "    - Java has never been run on this system" -ForegroundColor Gray
        Write-Host "    - Prefetch files have been cleared" -ForegroundColor Gray
        Write-Host "    - Prefetch is disabled" -ForegroundColor Gray
        return
    }
    
    Write-Host "[+] Found $($javaFiles.Count) JAVA prefetch file(s)" -ForegroundColor Green
    Write-Host ""
    
    $allJarPaths = @()
    $fileMetadata = @{}
    $processedFiles = 0
    $successfulParsing = 0
    
    foreach ($sysFile in $javaFiles) {
        $processedFiles++
        Write-Progress -Activity "Extracting Indexes" `
                      -Status "Processing file $processedFiles of $($javaFiles.Count)" `
                      -PercentComplete (($processedFiles / $javaFiles.Count) * 100)
        
        if ($script:DebugMode) {
            Write-Host ""
            Write-Host "[DEBUG] ======================================" -ForegroundColor Magenta
        }
        
        $indexes = Get-SystemIndexes -FilePath $sysFile.FullName
        
        if ($indexes.Count -eq 0) {
            if ($script:DebugMode) {
                Write-Host "  [DEBUG] No indexes extracted from $($sysFile.Name)" -ForegroundColor Yellow
            }
            continue
        }
        
        $successfulParsing++
        
        if ($script:DebugMode) {
            Write-Host "  [DEBUG] Successfully extracted $($indexes.Count) paths" -ForegroundColor Green
        }
        
        $indexNum = 0
        foreach ($index in $indexes) {
            $indexNum++
            
            if ($index -match '\\VOLUME\{[^\}]+\}\\(.*)$') {
                $relativePath = $Matches[1]
                $assumedPath = "C:\$relativePath"
                $allJarPaths += $assumedPath
                
                if (-not $fileMetadata.ContainsKey($assumedPath)) {
                    $fileMetadata[$assumedPath] = @{
                        SourceFile = $sysFile.Name
                        IndexNumber = $indexNum
                        OriginalPath = $index
                    }
                }
            }
            else {
                $allJarPaths += $index
                
                if (-not $fileMetadata.ContainsKey($index)) {
                    $fileMetadata[$index] = @{
                        SourceFile = $sysFile.Name
                        IndexNumber = $indexNum
                        OriginalPath = $index
                    }
                }
            }
        }
    }
    
    Write-Progress -Activity "Extracting Indexes" -Completed
    
    Write-Host ""
    Write-Host "[+] Prefetch files successfully parsed: $successfulParsing / $processedFiles" -ForegroundColor Green
    Write-Host "[+] Total file paths extracted: $($allJarPaths.Count)" -ForegroundColor Green
    
    if ($allJarPaths.Count -eq 0) {
        Write-Host ""
        Write-Host "[!] No file paths could be extracted from prefetch files" -ForegroundColor Yellow
        Write-Host "[*] Possible issues:" -ForegroundColor Yellow
        Write-Host "    - Prefetch parsing failed (incompatible format)" -ForegroundColor Gray
        Write-Host "    - No Java applications with file references" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[*] Try running with -Debug flag for more information:" -ForegroundColor Cyan
        Write-Host "    .\doomsday-scanner-usn.ps1 -Debug" -ForegroundColor White
        return
    }
    
    $uniquePaths = $allJarPaths | Select-Object -Unique
    Write-Host "[+] Unique files to scan: $($uniquePaths.Count)" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "[*] Checking file existence across all drives..." -ForegroundColor Cyan
    Write-Host ""
    
    $existingPaths = @{}
    $trulyMissingPaths = @()
    $checkCount = 0
    $outsideRangeCount = 0
    $resolvedToDifferentDrive = 0
    
    $allDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' } | ForEach-Object { $_.Root.Substring(0, 1) }
    
    foreach ($path in $uniquePaths) {
        $checkCount++
        $foundPath = $null
        
        if (Test-Path $path -PathType Leaf) {
            $foundPath = $path
        }
        else {
            if ($path -match '^[A-Z]:\\(.*)$') {
                $relativePath = $Matches[1]
                
                foreach ($drive in $allDrives) {
                    $testPath = "$drive`:\$relativePath"
                    
                    if (Test-Path $testPath -PathType Leaf) {
                        $foundPath = $testPath
                        $resolvedToDifferentDrive++
                        
                        if ($script:DebugMode) {
                            Write-Host "  [DEBUG] Found on different drive: $testPath (assumed $path)" -ForegroundColor Cyan
                        }
                        break
                    }
                }
            }
        }
        
        if ($foundPath) {
            $fileSize = (Get-Item $foundPath -ErrorAction SilentlyContinue).Length
            
            if ($fileSize -ge 200KB -and $fileSize -le 15MB) {
                $existingPaths[$path] = $foundPath
            } else {
                $outsideRangeCount++
                if ($script:DebugMode) {
                    $sizeMB = [math]::Round($fileSize / 1MB, 2)
                    Write-