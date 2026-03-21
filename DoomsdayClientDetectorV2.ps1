#Requires -Version 5.1

param(
    [switch]$Debug,
    [switch]$NoUSN
)

<#
    Doomsday Client Scanner v2
    Improved Prefetch + USN + Archive Heuristics Scanner

    Credits:
    TeslaPro @teamwsf
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# =========================
# Global Settings
# =========================
$script:DebugMode = $false
$script:UseUSN = $true
$script:RecentFileActivity = @{}
$script:USNSearched = $false

$script:MinFileSize = 200KB
$script:MaxFileSize = 15MB
$script:USNMinutesBack = 120
$script:MaxJarClassCount = 30
$script:MaxExtractedStrings = 2000

# =========================
# Banner
# =========================
function Show-Banner {
    $duck1 = @"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡏⠉⢻⣷⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣾⣿⣿⣶⣶⣶⣦⣤⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⠏⠉⠉⠉⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⠿⠟⠀⠀⠀⠀⠀⠀⠀⠀
"@

    $duck2 = @"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⣤⣤⣤⣶⣾⣷⣄⠀⠀⠀⠀⠀
⠀⠀⣶⣤⣤⣤⣤⣤⣤⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⠛⢻⣿⣿⣿⡆⠀⠀⠀⠀
⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⢀⣿⣿⣿⣿⡇⠀⠀⠀⠀
⠀⠀⠈⢿⣿⣿⣏⡈⠛⠿⠿⣿⣿⣿⠿⠿⠟⠋⣁⣴⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠙⠿⣿⣿⣶⣦⣤⣤⣤⣤⣤⣴⣶⣿⣿⣿⣿⣿⣿⡿⠏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠻⠿⠿⠿⢿⡿⠿⠿⠿⠟⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀
"@

    $duck3 = @"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡄⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣧⣾⣶⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"@

    Write-Host $duck1 -ForegroundColor Yellow
    Write-Host $duck2 -ForegroundColor White
    Write-Host $duck3 -ForegroundColor Yellow
    Write-Host ""

    Write-Host "                    Made by " -NoNewline
    Write-Host "TeslaPro " -NoNewline -ForegroundColor White
    Write-Host "@" -NoNewline -ForegroundColor Blue
    Write-Host "teamwsf" -ForegroundColor Yellow

    Write-Host ""
    Write-Host "                    Doomsday Client Scanner v2" -ForegroundColor Cyan
    Write-Host "                    Prefetch + USN + Archive Heuristics" -ForegroundColor DarkCyan
    Write-Host ""
}

# =========================
# Helper Functions
# =========================
function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-DebugLog {
    param([string]$Message)
    if ($script:DebugMode) {
        Write-Host "[DEBUG] $Message" -ForegroundColor Magenta
    }
}

function Get-NTFSDrives {
    $ntfsDrives = @()
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }

    foreach ($drive in $drives) {
        try {
            $driveLetter = $drive.Root.Substring(0, 1)
            $volume = Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue
            if ($volume -and $volume.FileSystem -eq 'NTFS') {
                $ntfsDrives += $driveLetter
            }
        } catch {
            continue
        }
    }

    return $ntfsDrives
}

function Get-FileSHA256 {
    param([string]$Path)
    try {
        return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        return $null
    }
}

function Test-FileInSizeRange {
    param(
        [string]$Path,
        [long]$MinBytes = $script:MinFileSize,
        [long]$MaxBytes = $script:MaxFileSize
    )

    if (-not (Test-Path $Path -PathType Leaf)) {
        return $false
    }

    try {
        $size = (Get-Item $Path -ErrorAction Stop).Length
        return ($size -ge $MinBytes -and $size -le $MaxBytes)
    } catch {
        return $false
    }
}

# =========================
# Prefetch Decompression
# =========================
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
        if (compressed == null || compressed.Length < 8) return null;
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

            uint status = RtlDecompressBufferEx(
                4,
                result,
                uncompSize,
                compData,
                compData.Length,
                out finalSize,
                workspace
            );

            if (status != 0) return null;
            return result;
        }
        finally {
            Marshal.FreeHGlobal(workspace);
        }
    }
}
"@

function Get-PrefetchVersion {
    param([byte[]]$Data)

    if (-not $Data -or $Data.Length -lt 8) {
        return 0
    }

    $sig = [System.Text.Encoding]::ASCII.GetString($Data, 4, 4)
    if ($sig -ne "SCCA") {
        return 0
    }

    return [BitConverter]::ToUInt32($Data, 0)
}

function Get-SystemIndexes {
    param([string]$FilePath)

    try {
        $data = [System.IO.File]::ReadAllBytes($FilePath)

        if (-not $data -or $data.Length -lt 8) {
            return @()
        }

        $isCompressed = ($data[0] -eq 0x4D -and $data[1] -eq 0x41 -and $data[2] -eq 0x4D)
        Write-DebugLog "Parsing prefetch: $([System.IO.Path]::GetFileName($FilePath)) | Compressed=$isCompressed"

        if ($isCompressed) {
            $data = [NtdllDecompressor]::Decompress($data)
            if (-not $data) {
                Write-Warning "Failed to decompress prefetch file: $FilePath"
                return @()
            }
        }

        if ($data.Length -lt 108) {
            Write-Warning "Prefetch file too small: $FilePath"
            return @()
        }

        $version = Get-PrefetchVersion -Data $data
        if ($version -notin 17, 23, 26, 30, 31) {
            Write-DebugLog "Unknown or unsupported prefetch version $version in $FilePath"
        }

        $sig = [System.Text.Encoding]::ASCII.GetString($data, 4, 4)
        if ($sig -ne 'SCCA') {
            Write-Warning "Invalid prefetch signature: $FilePath"
            return @()
        }

        $stringsOffset = [BitConverter]::ToUInt32($data, 100)
        $stringsSize   = [BitConverter]::ToUInt32($data, 104)

        if ($stringsOffset -le 0 -or $stringsSize -le 0) {
            return @()
        }

        if ($stringsOffset -ge $data.Length -or ($stringsOffset + $stringsSize) -gt $data.Length) {
            Write-DebugLog "Prefetch string section out of bounds: $FilePath"
            return @()
        }

        $paths = New-Object System.Collections.Generic.List[string]
        $pos = $stringsOffset
        $endPos = $stringsOffset + $stringsSize

        while ($pos -lt $endPos -and $pos -lt ($data.Length - 2)) {
            $nullPos = $pos

            while ($nullPos -lt ($data.Length - 1)) {
                if ($data[$nullPos] -eq 0 -and $data[$nullPos + 1] -eq 0) {
                    break
                }
                $nullPos += 2
            }

            if ($nullPos -gt $pos) {
                $strLen = $nullPos - $pos
                if ($strLen -gt 0 -and $strLen -lt 4096) {
                    try {
                        $value = [System.Text.Encoding]::Unicode.GetString($data, $pos, $strLen)
                        if (-not [string]::IsNullOrWhiteSpace($value)) {
                            $paths.Add($value)
                        }
                    } catch {}
                }
            }

            $pos = $nullPos + 2

            if ($paths.Count -ge $script:MaxExtractedStrings) {
                break
            }
        }

        return $paths.ToArray()
    } catch {
        Write-Warning "Error parsing prefetch file $FilePath : $_"
        return @()
    }
}

# =========================
# USN Functions
# =========================
function Get-RecentUSNFileActivity {
    param(
        [string[]]$DriveLetters,
        [int]$MinutesBack = 120
    )

    if ($script:USNSearched) {
        return $script:RecentFileActivity
    }

    $allActivity = @{}
    $cutoffTime = (Get-Date).AddMinutes(-$MinutesBack)

    foreach ($driveLetter in $DriveLetters) {
        try {
            Write-Host "[*] Reading USN Journal on drive $driveLetter`: (last $MinutesBack minutes)..." -ForegroundColor Cyan

            $usnOutput = & fsutil usn readjournal "$driveLetter`:" 2>$null

            if ($LASTEXITCODE -ne 0 -or -not $usnOutput) {
                Write-Host "[!] Could not read USN Journal on drive $driveLetter`:" -ForegroundColor Yellow
                continue
            }

            $currentFile = $null
            $currentTime = $null
            $currentReason = $null
            $driveHits = 0

            foreach ($line in $usnOutput) {
                if ([string]::IsNullOrWhiteSpace($line)) {
                    continue
                }

                if ($line -match 'File name\s+:\s*(.+)$') {
                    $currentFile = $Matches[1].Trim()
                }
                elseif ($line -match 'Time stamp\s+:\s*(.+)$') {
                    try {
                        $currentTime = [DateTime]::Parse($Matches[1].Trim())
                    } catch {
                        $currentTime = $null
                    }
                }
                elseif ($line -match 'Reason\s+:\s*(.+)$') {
                    $currentReason = $Matches[1].Trim()

                    if ($currentFile -and $currentTime -and $currentTime -gt $cutoffTime) {
                        $reasonUpper = $currentReason.ToUpperInvariant()

                        $isInteresting = (
                            $reasonUpper -match 'FILE_DELETE' -or
                            $reasonUpper -match 'RENAME_OLD_NAME' -or
                            $reasonUpper -match 'RENAME_NEW_NAME' -or
                            $reasonUpper -match 'CLOSE'
                        )

                        if ($isInteresting) {
                            $fullKey = "$driveLetter`:\$currentFile"

                            if (-not $allActivity.ContainsKey($fullKey) -or $allActivity[$fullKey].Timestamp -lt $currentTime) {
                                $allActivity[$fullKey] = [PSCustomObject]@{
                                    Path      = $fullKey
                                    Timestamp = $currentTime
                                    Reason    = $currentReason
                                    Drive     = $driveLetter
                                }
                                $driveHits++
                            }
                        }
                    }

                    $currentFile = $null
                    $currentTime = $null
                    $currentReason = $null
                }
            }

            Write-Host "[+] Drive $driveLetter`: - Found $driveHits interesting recent USN entries" -ForegroundColor Green
        } catch {
            Write-Host "[!] Error reading USN Journal on drive $driveLetter`: - $_" -ForegroundColor Yellow
        }
    }

    $script:RecentFileActivity = $allActivity
    $script:USNSearched = $true

    Write-Host ""
    Write-Host "[+] Total recent interesting USN entries: $($allActivity.Count)" -ForegroundColor Green
    Write-Host ""

    return $allActivity
}

function Test-RecentlyDeletedOrRenamed {
    param([string]$FilePath)

    if (-not $script:RecentFileActivity -or $script:RecentFileActivity.Count -eq 0) {
        return $null
    }

    if ($script:RecentFileActivity.ContainsKey($FilePath)) {
        return $script:RecentFileActivity[$FilePath]
    }

    $fileName = [System.IO.Path]::GetFileName($FilePath)

    foreach ($key in $script:RecentFileActivity.Keys) {
        if ($key -like "*\$fileName") {
            return $script:RecentFileActivity[$key]
        }
    }

    return $null
}

# =========================
# Detection Patterns
# =========================
$script:BytePatterns = @(
    @{
        Name  = "Pattern #1"
        Bytes = "6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A160C14005C6588B800"
    },
    @{
        Name  = "Pattern #2"
        Bytes = "0C1504851D85160A6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A16"
    },
    @{
        Name  = "Pattern #3"
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
    param([string]$HexString)

    $bytes = New-Object byte[] ($HexString.Length / 2)
    for ($i = 0; $i -lt $HexString.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($HexString.Substring($i, 2), 16)
    }
    return $bytes
}

function Search-BytePattern {
    param(
        [byte[]]$Data,
        [byte[]]$Pattern
    )

    if (-not $Data -or -not $Pattern) { return $false }
    if ($Pattern.Length -gt $Data.Length) { return $false }

    $patternLength = $Pattern.Length
    $dataLength = $Data.Length

    for ($i = 0; $i -le ($dataLength - $patternLength); $i++) {
        $match = $true

        for ($j = 0; $j -lt $patternLength; $j++) {
            if ($Data[$i + $j] -ne $Pattern[$j]) {
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
        [byte[]]$Data,
        [string]$ClassName
    )

    $classBytes = [System.Text.Encoding]::ASCII.GetBytes($ClassName)
    return Search-BytePattern -Data $Data -Pattern $classBytes
}

# =========================
# Archive Helpers
# =========================
function Test-ZipMagicBytes {
    param([string]$Path)

    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            if ($stream.Length -lt 4) {
                return $false
            }

            $buffer = New-Object byte[] 4
            [void]$stream.Read($buffer, 0, 4)

            return ($buffer[0] -eq 0x50 -and $buffer[1] -eq 0x4B)
        } finally {
            $stream.Dispose()
        }
    } catch {
        return $false
    }
}

function Get-JarMetadata {
    param([string]$Path)

    $result = [PSCustomObject]@{
        IsZip               = $false
        IsJarLike           = $false
        HasManifest         = $false
        ClassCount          = 0
        SingleLetterClasses = @()
        EntryNames          = @()
        Error               = $null
    }

    try {
        $result.IsZip = Test-ZipMagicBytes -Path $Path
        if (-not $result.IsZip) {
            return $result
        }

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $jar = [System.IO.Compression.ZipFile]::OpenRead($Path)

        try {
            $entries = $jar.Entries
            $result.EntryNames = $entries | Select-Object -ExpandProperty FullName

            $classFiles = $entries | Where-Object { $_.FullName -like "*.class" }
            $result.ClassCount = @($classFiles).Count

            $result.HasManifest = ($result.EntryNames -contains "META-INF/MANIFEST.MF")
            $result.IsJarLike = ($result.ClassCount -gt 0)

            foreach ($entry in $classFiles) {
                $parts = $entry.FullName -split '/'
                $fileName = $parts[-1]
                $classNameOnly = $fileName -replace '\.class$', ''

                if ($classNameOnly -match '^[a-zA-Z]$') {
                    if ($parts.Length -gt 1) {
                        $result.SingleLetterClasses += (($parts[0..($parts.Length - 2)] -join '/') + '/' + $classNameOnly)
                    } else {
                        $result.SingleLetterClasses += $classNameOnly
                    }
                }
            }
        } finally {
            $jar.Dispose()
        }
    } catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

# =========================
# Scoring
# =========================
function Get-DetectionScore {
    param(
        [int]$ByteMatchCount,
        [int]$ClassMatchCount,
        [int]$SingleLetterCount,
        [bool]$IsRenamedJar,
        [bool]$HasManifest,
        [bool]$HasRecentUSN
    )

    $score = 0
    $reasons = New-Object System.Collections.Generic.List[string]

    if ($ByteMatchCount -ge 1) {
        $score += 50
        $reasons.Add("Byte signature match")
    }

    if ($ByteMatchCount -ge 2) {
        $score += 20
        $reasons.Add("Multiple byte signature matches")
    }

    if ($ClassMatchCount -ge 5) {
        $score += 15
        $reasons.Add("Multiple suspicious class name references")
    } elseif ($ClassMatchCount -ge 3) {
        $score += 8
        $reasons.Add("Some suspicious class name references")
    }

    if ($SingleLetterCount -ge 8) {
        $score += 15
        $reasons.Add("Heavy single-letter class obfuscation")
    } elseif ($SingleLetterCount -ge 5) {
        $score += 8
        $reasons.Add("Moderate single-letter class obfuscation")
    }

    if ($IsRenamedJar) {
        $score += 10
        $reasons.Add("Renamed JAR-like archive")
    }

    if ($HasManifest) {
        $score += 3
        $reasons.Add("Contains JAR manifest")
    }

    if ($HasRecentUSN) {
        $score += 20
        $reasons.Add("Recent delete or rename activity found in USN")
    }

    $confidence = "NONE"
    switch ($score) {
        { $_ -ge 80 } { $confidence = "HIGH"; break }
        { $_ -ge 50 } { $confidence = "MEDIUM"; break }
        { $_ -ge 25 } { $confidence = "LOW"; break }
        default       { $confidence = "NONE" }
    }

    return [PSCustomObject]@{
        Score      = $score
        Confidence = $confidence
        Reasons    = $reasons.ToArray()
    }
}

# =========================
# Main Archive Detection
# =========================
function Test-DoomsdayClient {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [object]$RecentUSNEvent = $null
    )

    $result = [PSCustomObject]@{
        IsDetected          = $false
        Confidence          = "NONE"
        Score               = 0
        BytePatternMatches  = @()
        ClassNameMatches    = @()
        SingleLetterClasses = @()
        IsRenamedJar        = $false
        HasManifest         = $false
        ClassCount          = 0
        SHA256              = $null
        DetectionReasons    = @()
        Error               = $null
    }

    if (-not (Test-Path $Path -PathType Leaf)) {
        $result.Error = "File not found"
        return $result
    }

    try {
        $fileExtension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
        $jarMeta = Get-JarMetadata -Path $Path

        if (-not $jarMeta.IsZip) {
            $result.Error = "File is not ZIP or JAR-like"
            return $result
        }

        if ($jarMeta.Error) {
            $result.Error = $jarMeta.Error
            return $result
        }

        $result.ClassCount = $jarMeta.ClassCount
        $result.SingleLetterClasses = $jarMeta.SingleLetterClasses
        $result.HasManifest = $jarMeta.HasManifest
        $result.SHA256 = Get-FileSHA256 -Path $Path

        if (-not $jarMeta.IsJarLike) {
            $result.Error = "ZIP archive does not appear to be JAR-like (no .class files)"
            return $result
        }

        if ($fileExtension -ne ".jar" -and $jarMeta.ClassCount -gt 0) {
            $result.IsRenamedJar = $true
        }

        if ($jarMeta.ClassCount -gt $script:MaxJarClassCount) {
            $result.Error = "Skipped: Too many classes ($($jarMeta.ClassCount)) - likely legitimate library"
            return $result
        }

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $jar = [System.IO.Compression.ZipFile]::OpenRead($Path)

        try {
            $classFiles = $jar.Entries | Where-Object { $_.FullName -like "*.class" }

            $foundBytePatterns = New-Object System.Collections.Generic.HashSet[string]
            $foundClassPatterns = New-Object System.Collections.Generic.HashSet[string]

            $compiledPatterns = @()
            foreach ($pattern in $script:BytePatterns) {
                $compiledPatterns += [PSCustomObject]@{
                    Name  = $pattern.Name
                    Bytes = ConvertHex-ToBytes -HexString $pattern.Bytes
                }
            }

            foreach ($entry in $classFiles) {
                $stream = $entry.Open()
                try {
                    $reader = New-Object System.IO.BinaryReader($stream)
                    $bytes = $reader.ReadBytes([int]$entry.Length)
                    $reader.Close()

                    foreach ($pattern in $compiledPatterns) {
                        if (-not $foundBytePatterns.Contains($pattern.Name)) {
                            if (Search-BytePattern -Data $bytes -Pattern $pattern.Bytes) {
                                [void]$foundBytePatterns.Add($pattern.Name)
                            }
                        }
                    }

                    foreach ($className in $script:ClassPatterns) {
                        if (-not $foundClassPatterns.Contains($className)) {
                            if (Search-ClassPattern -Data $bytes -ClassName $className) {
                                [void]$foundClassPatterns.Add($className)
                            }
                        }
                    }
                } finally {
                    $stream.Dispose()
                }
            }

            $result.BytePatternMatches = $foundBytePatterns.ToArray()
            $result.ClassNameMatches = $foundClassPatterns.ToArray()
        } finally {
            $jar.Dispose()
        }

        $hasRecentUSN = $false
        if ($null -ne $RecentUSNEvent) {
            $hasRecentUSN = $true
        }

        $scoreResult = Get-DetectionScore `
            -ByteMatchCount $result.BytePatternMatches.Count `
            -ClassMatchCount $result.ClassNameMatches.Count `
            -SingleLetterCount $result.SingleLetterClasses.Count `
            -IsRenamedJar $result.IsRenamedJar `
            -HasManifest $result.HasManifest `
            -HasRecentUSN $hasRecentUSN

        $result.Score = $scoreResult.Score
        $result.Confidence = $scoreResult.Confidence
        $result.DetectionReasons = $scoreResult.Reasons
        $result.IsDetected = ($result.Confidence -ne "NONE")
    } catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

# =========================
# Main Scanner
# =========================
function Start-DoomsdayScan {
    param(
        [switch]$Debug,
        [switch]$NoUSN
    )

    $script:DebugMode = $Debug
    $script:UseUSN = -not $NoUSN

    Show-Banner

    if (-not (Test-Administrator)) {
        Write-Host ""
        Write-Host "ERROR: " -ForegroundColor Red -NoNewline
        Write-Host "Administrator privileges required!"
        Write-Host ""
        Write-Host "Please launch PowerShell as Administrator." -ForegroundColor Yellow
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

    $systemPath = "C:\Windows\Prefetch"
    if (-not (Test-Path $systemPath)) {
        Write-Host "[!] Prefetch directory not found: $systemPath" -ForegroundColor Red
        return
    }

    Write-Host "[*] Extracting file references from JAVA prefetch files..." -ForegroundColor Cyan
    Write-Host ""

    $javaFiles = Get-ChildItem -Path $systemPath -Filter "JAVA*.EXE-*.pf" -ErrorAction SilentlyContinue

    if (-not $javaFiles -or $javaFiles.Count -eq 0) {
        Write-Host "[!] No JAVA prefetch files found in $systemPath" -ForegroundColor Yellow
        Write-Host "[*] This may mean:" -ForegroundColor Yellow
        Write-Host "    - Java has not been executed on this system" -ForegroundColor Gray
        Write-Host "    - Prefetch has been disabled or cleared" -ForegroundColor Gray
        Write-Host ""
        return
    }

    Write-Host "[+] Found $($javaFiles.Count) JAVA prefetch file(s)" -ForegroundColor Green
    Write-Host ""

    $allExtractedPaths = @()
    $fileMetadata = @{}
    $processedFiles = 0
    $successfulParsing = 0

    foreach ($sysFile in $javaFiles) {
        $processedFiles++
        Write-Progress -Activity "Parsing Prefetch" -Status "Processing $processedFiles / $($javaFiles.Count)" -PercentComplete (($processedFiles / $javaFiles.Count) * 100)

        $indexes = Get-SystemIndexes -FilePath $sysFile.FullName

        if (-not $indexes -or $indexes.Count -eq 0) {
            continue
        }

        $successfulParsing++
        $indexNum = 0

        foreach ($index in $indexes) {
            $indexNum++

            if ($index -match '\\VOLUME\{[^\}]+\}\\(.*)$') {
                $relativePath = $Matches[1]
                $assumedPath = "C:\$relativePath"
                $allExtractedPaths += $assumedPath

                if (-not $fileMetadata.ContainsKey($assumedPath)) {
                    $fileMetadata[$assumedPath] = [PSCustomObject]@{
                        SourceFile   = $sysFile.Name
                        IndexNumber  = $indexNum
                        OriginalPath = $index
                    }
                }
            } else {
                $allExtractedPaths += $index

                if (-not $fileMetadata.ContainsKey($index)) {
                    $fileMetadata[$index] = [PSCustomObject]@{
                        SourceFile   = $sysFile.Name
                        IndexNumber  = $indexNum
                        OriginalPath = $index
                    }
                }
            }
        }
    }

    Write-Progress -Activity "Parsing Prefetch" -Completed

    Write-Host ""
    Write-Host "[+] Prefetch files successfully parsed: $successfulParsing / $processedFiles" -ForegroundColor Green
    Write-Host "[+] Total file references extracted: $($allExtractedPaths.Count)" -ForegroundColor Green

    if (-not $allExtractedPaths -or $allExtractedPaths.Count -eq 0) {
        Write-Host ""
        Write-Host "[!] No file paths could be extracted from JAVA prefetch files." -ForegroundColor Yellow
        return
    }

    $uniquePaths = $allExtractedPaths | Select-Object -Unique
    Write-Host "[+] Unique extracted references: $($uniquePaths.Count)" -ForegroundColor Green
    Write-Host ""

    if ($script:UseUSN) {
        $ntfsDrives = Get-NTFSDrives
        if ($ntfsDrives.Count -gt 0) {
            [void](Get-RecentUSNFileActivity -DriveLetters $ntfsDrives -MinutesBack $script:USNMinutesBack)
        }
    }

    Write-Host "[*] Resolving files across all local drives..." -ForegroundColor Cyan
    Write-Host ""

    $existingPaths = @{}
    $missingPaths = @()
    $outsideRangePaths = @()
    $resolvedToDifferentDrive = 0

    $allDrives = Get-PSDrive -PSProvider FileSystem |
        Where-Object { $_.Root -match '^[A-Z]:\\$' } |
        ForEach-Object { $_.Root.Substring(0, 1) }

    foreach ($path in $uniquePaths) {
        $foundPath = $null

        if (Test-Path $path -PathType Leaf) {
            $foundPath = $path
        } elseif ($path -match '^[A-Z]:\\(.*)$') {
            $relativePath = $Matches[1]

            foreach ($drive in $allDrives) {
                $testPath = "$drive`:\$relativePath"
                if (Test-Path $testPath -PathType Leaf) {
                    $foundPath = $testPath
                    $resolvedToDifferentDrive++
                    break
                }
            }
        }

        if ($foundPath) {
            if (Test-FileInSizeRange -Path $foundPath) {
                $existingPaths[$path] = $foundPath
            } else {
                $outsideRangePaths += $foundPath
            }
        } else {
            $missingPaths += $path
        }
    }

    Write-Host "[+] Existing files in size range: $($existingPaths.Count)" -ForegroundColor Green
    if ($resolvedToDifferentDrive -gt 0) {
        Write-Host "[+] Files resolved to different drives: $resolvedToDifferentDrive" -ForegroundColor Cyan
    }
    Write-Host "[!] Existing files outside size range: $($outsideRangePaths.Count)" -ForegroundColor Gray
    Write-Host "[!] Missing files: $($missingPaths.Count)" -ForegroundColor Yellow
    Write-Host ""

    if ($missingPaths.Count -gt 0) {
        Write-Host "[*] Missing files referenced by JAVA prefetch:" -ForegroundColor Cyan
        Write-Host ""

        $displayedMissing = 0

        foreach ($missingPath in $missingPaths) {
            if ($missingPath -match '\\TEMP\\|\\TMP\\|HSPERFDATA|\.TMP$|JNA\d+\.DLL') {
                continue
            }

            if ($missingPath -notmatch '\.(JAR|ZIP|EXE|DLL|DAT)$' -and $missingPath -notmatch '^[A-Z]:\\[^.]+$') {
                continue
            }

            $displayedMissing++
            Write-Host "  [MISSING] " -NoNewline -ForegroundColor Yellow
            Write-Host $missingPath -ForegroundColor White

            if ($fileMetadata.ContainsKey($missingPath)) {
                Write-Host "      Source Prefetch: $($fileMetadata[$missingPath].SourceFile)" -ForegroundColor Cyan
            }

            $usnEvent = Test-RecentlyDeletedOrRenamed -FilePath $missingPath
            if ($usnEvent) {
                Write-Host "      Recent USN: $($usnEvent.Timestamp) | $($usnEvent.Reason)" -ForegroundColor Yellow
            }
        }

        if ($displayedMissing -eq 0) {
            Write-Host "  No suspicious missing references worth displaying." -ForegroundColor Green
        }

        Write-Host ""
    }

    if ($existingPaths.Count -eq 0) {
        Write-Host "[!] No existing files remain to scan." -ForegroundColor Yellow
        return
    }

    Write-Host "[*] Scanning archive candidates for Doomsday Client indicators..." -ForegroundColor Cyan
    Write-Host ""

    $detections = @()
    $scanned = 0
    $skipped = 0
    $scanResults = @()

    foreach ($assumedPath in $existingPaths.Keys) {
        $actualPath = $existingPaths[$assumedPath]
        $scanned++

        Write-Progress -Activity "Scanning Files" -Status "$scanned / $($existingPaths.Count)" -PercentComplete (($scanned / $existingPaths.Count) * 100)

        $possibleUSN = Test-RecentlyDeletedOrRenamed -FilePath $actualPath
        $result = Test-DoomsdayClient -Path $actualPath -RecentUSNEvent $possibleUSN

        $fileItem = Get-Item $actualPath -ErrorAction SilentlyContinue

        $sizeBytes = $null
        $creationTimeUtc = $null
        $lastWriteTimeUtc = $null
        $lastAccessTimeUtc = $null
        $sourceFile = $null
        $indexNumber = $null

        if ($fileItem) {
            $sizeBytes = $fileItem.Length
            $creationTimeUtc = $fileItem.CreationTimeUtc
            $lastWriteTimeUtc = $fileItem.LastWriteTimeUtc
            $lastAccessTimeUtc = $fileItem.LastAccessTimeUtc
        }

        if ($fileMetadata.ContainsKey($assumedPath)) {
            $sourceFile = $fileMetadata[$assumedPath].SourceFile
            $indexNumber = $fileMetadata[$assumedPath].IndexNumber
        }

        $record = [PSCustomObject]@{
            Path               = $actualPath
            AssumedPath        = $assumedPath
            Exists             = $true
            SizeBytes          = $sizeBytes
            CreationTimeUtc    = $creationTimeUtc
            LastWriteTimeUtc   = $lastWriteTimeUtc
            LastAccessTimeUtc  = $lastAccessTimeUtc
            SourceFile         = $sourceFile
            IndexNumber        = $indexNumber
            SHA256             = $result.SHA256
            ClassCount         = $result.ClassCount
            BytePatternMatches = $result.BytePatternMatches
            ClassNameMatches   = $result.ClassNameMatches
            SingleLetterClasses= $result.SingleLetterClasses
            IsRenamedJar       = $result.IsRenamedJar
            HasManifest        = $result.HasManifest
            Score              = $result.Score
            Confidence         = $result.Confidence
            DetectionReasons   = $result.DetectionReasons
            Error              = $result.Error
        }

        $scanResults += $record

        if ($result.Error -and $result.Error -like "Skipped:*") {
            $skipped++
        }

        if ($result.IsDetected) {
            $detections += $record

            Write-Host "[!] DETECTION: " -ForegroundColor Red -NoNewline
            Write-Host $actualPath -ForegroundColor White
            Write-Host "    Confidence: " -NoNewline

            switch ($result.Confidence) {
                "HIGH"   { Write-Host "HIGH" -ForegroundColor Red }
                "MEDIUM" { Write-Host "MEDIUM" -ForegroundColor Yellow }
                "LOW"    { Write-Host "LOW" -ForegroundColor Gray }
            }

            Write-Host "    Score: $($result.Score)" -ForegroundColor Cyan

            if ($result.IsRenamedJar) {
                Write-Host "    Renamed JAR-like archive: YES" -ForegroundColor Red
            }

            if ($result.BytePatternMatches.Count -gt 0) {
                Write-Host "    Byte patterns: $($result.BytePatternMatches -join ', ')" -ForegroundColor Red
            }

            if ($result.ClassNameMatches.Count -gt 0) {
                Write-Host "    Suspicious class references: $($result.ClassNameMatches.Count)" -ForegroundColor Yellow
            }

            if ($result.SingleLetterClasses.Count -gt 0) {
                Write-Host "    Single-letter classes: $($result.SingleLetterClasses.Count)" -ForegroundColor Yellow
            }

            if ($result.SHA256) {
                Write-Host "    SHA256: $($result.SHA256)" -ForegroundColor DarkGray
            }

            if ($result.DetectionReasons.Count -gt 0) {
                Write-Host "    Reasons: $($result.DetectionReasons -join '; ')" -ForegroundColor DarkCyan
            }

            Write-Host ""
        }
    }

    Write-Progress -Activity "Scanning Files" -Completed

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "SCAN COMPLETE" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Prefetch files parsed: $successfulParsing / $processedFiles"
    Write-Host "Total extracted references: $($allExtractedPaths.Count)"
    Write-Host "Unique extracted references: $($uniquePaths.Count)"
    Write-Host "Existing files in size range: $($existingPaths.Count)"
    Write-Host "Missing files: $($missingPaths.Count)"
    Write-Host "Skipped archives (> $($script:MaxJarClassCount) classes): $skipped" -ForegroundColor Gray
    Write-Host "Scanned files: $scanned"

    Write-Host "Doomsday detections: " -NoNewline
    if ($detections.Count -gt 0) {
        Write-Host $detections.Count -ForegroundColor Red
    } else {
        Write-Host "0" -ForegroundColor Green
    }

    Write-Host ""

    if ($detections.Count -gt 0) {
        $high = ($detections | Where-Object { $_.Confidence -eq "HIGH" }).Count
        $medium = ($detections | Where-Object { $_.Confidence -eq "MEDIUM" }).Count
        $low = ($detections | Where-Object { $_.Confidence -eq "LOW" }).Count

        Write-Host "Detections by confidence:" -ForegroundColor Yellow
        if ($high -gt 0)   { Write-Host "  HIGH:   $high" -ForegroundColor Red }
        if ($medium -gt 0) { Write-Host "  MEDIUM: $medium" -ForegroundColor Yellow }
        if ($low -gt 0)    { Write-Host "  LOW:    $low" -ForegroundColor Gray }

        Write-Host ""
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "DETECTION DETAILS" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host ""

        $num = 1
        foreach ($detection in $detections) {
            Write-Host "[$num] $($detection.Path)" -ForegroundColor White
            Write-Host "    Source Prefetch: $($detection.SourceFile)" -ForegroundColor Cyan
            Write-Host "    Index Number: #$($detection.IndexNumber)" -ForegroundColor Cyan
            Write-Host "    Score: $($detection.Score)" -ForegroundColor Cyan
            Write-Host "    Confidence: $($detection.Confidence)" -ForegroundColor Yellow
            Write-Host "    SHA256: $($detection.SHA256)" -ForegroundColor DarkGray
            Write-Host "    Class Count: $($detection.ClassCount)" -ForegroundColor Gray
            Write-Host "    Renamed JAR-like Archive: $($detection.IsRenamedJar)" -ForegroundColor Gray

            if ($detection.BytePatternMatches.Count -gt 0) {
                Write-Host "    Byte Pattern Matches: $($detection.BytePatternMatches -join ', ')" -ForegroundColor Red
            }
            if ($detection.ClassNameMatches.Count -gt 0) {
                Write-Host "    Class Name Matches: $($detection.ClassNameMatches -join ', ')" -ForegroundColor Yellow
            }
            if ($detection.SingleLetterClasses.Count -gt 0) {
                Write-Host "    Single-Letter Classes: $($detection.SingleLetterClasses.Count)" -ForegroundColor Yellow
            }
            if ($detection.DetectionReasons.Count -gt 0) {
                Write-Host "    Reasons: $($detection.DetectionReasons -join '; ')" -ForegroundColor DarkCyan
            }

            Write-Host ""
            $num++
        }
    } else {
        Write-Host "No Doomsday Client detected." -ForegroundColor Green
        Write-Host ""
    }

    $reportName = "doomsday-scan-v2-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".json"
    $reportPath = Join-Path -Path $PSScriptRoot -ChildPath $reportName

    $export = [PSCustomObject]@{
        ScanTimeUtc         = (Get-Date).ToUniversalTime()
        ComputerName        = $env:COMPUTERNAME
        UserName            = $env:USERNAME
        WindowsVersion      = "$($osVersion.Major).$($osVersion.Minor).$($osVersion.Build)"
        PrefetchFilesParsed = $successfulParsing
        TotalPrefetchFiles  = $processedFiles
        ExtractedReferences = $allExtractedPaths.Count
        UniqueReferences    = $uniquePaths.Count
        ExistingFiles       = $existingPaths.Count
        MissingFiles        = $missingPaths.Count
        SkippedFiles        = $skipped
        Detections          = $detections
        AllScanResults      = $scanResults
    }

    try {
        $export | ConvertTo-Json -Depth 8 | Out-File -FilePath $reportPath -Encoding UTF8
        Write-Host "[+] JSON report written to: $reportPath" -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to export JSON report: $_" -ForegroundColor Yellow
    }

    if ($script:DebugMode) {
        Write-Host ""
        Write-Host "[DEBUG MODE] Scan completed with debugging enabled." -ForegroundColor Magenta
    }
}

Start-DoomsdayScan -Debug:$Debug -NoUSN:$NoUSN