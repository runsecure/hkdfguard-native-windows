<#
.SYNOPSIS
Writes the seed corpora for fuzz_kek_dacl and fuzz_v2_kdf.

.DESCRIPTION
    powershell -File tests\fuzz\Make-Seeds.ps1

Each seed is a well-formed input for its target, so fuzzing starts from
realistic structure: a KEK's DACL, a pair of KDF inputs. The seeds are
checked in under tests/fuzz/corpus/<target>/; rerun this after changing a
format. Nothing here is secret.

Runs under Windows PowerShell 5.1 and PowerShell 7; needs nothing else.
(Make-AbiSeeds.ps1 writes the seeds of the C ABI targets, which the build
generates rather than checks in.)
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# The concatenation of its arguments, each a byte array.
function Join {
    $out = New-Object System.IO.MemoryStream
    foreach ($part in $args) {
        $bytes = [byte[]]$part
        $out.Write($bytes, 0, $bytes.Length)
    }
    return , $out.ToArray()
}

function U8([int]$N) { return , [byte[]]@($N -band 0xFF) }
function U16([int]$N) { return , [BitConverter]::GetBytes([uint16]$N) }
function U32([long]$N) { return , [BitConverter]::GetBytes([uint32]$N) }
function Ascii([string]$Text) { return , [Text.Encoding]::ASCII.GetBytes($Text) }

function Write-Seed([string]$Target, [string]$Name, [byte[]]$Data) {
    $folder = Join-Path (Join-Path $PSScriptRoot 'corpus') $Target
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $folder $Name), $Data)
}

# ---- fuzz_kek_dacl: an unused byte, then a KEK's DACL (little-endian) ----

# A SID: revision 1, the sub-authority count, the authority (6 bytes,
# big-endian), then each sub-authority.
function Sid([long]$Authority, [long[]]$Subs = @()) {
    $le = [BitConverter]::GetBytes([uint64]$Authority)  # little-endian, 8 bytes
    $bigEndian6 = [byte[]]@($le[5], $le[4], $le[3], $le[2], $le[1], $le[0])
    $out = Join (U8 1) (U8 $Subs.Count) $bigEndian6
    foreach ($s in $Subs) { $out = Join $out (U32 $s) }
    return , $out
}

function Ace([int]$Type, [int]$Flags, [long]$Mask, [byte[]]$SidBytes) {
    return Join (U8 $Type) (U8 $Flags) (U16 (8 + $SidBytes.Length)) (U32 $Mask) $SidBytes
}

function Acl {
    $body = [byte[]]@()
    foreach ($ace in $args) { $body = Join $body $ace }
    return Join (U8 2) (U8 0) (U16 (8 + $body.Length)) (U16 $args.Count) (U16 0) $body
}

$System = Sid 5 @(18)
$Admins = Sid 5 @(32, 544)
$Users = Sid 5 @(32, 545)
$Everyone = Sid 1 @(0)
$GenericAll = 0x10000000L
$GenericRead = 0x80000000L
$FileWriteData = 0x2L

Write-Seed 'fuzz_kek_dacl' 'kek_dacl' (Join (U8 0) (Acl (Ace 0 0 $GenericAll $System) (Ace 0 0 $GenericAll $Admins) `
            (Ace 0 0 $GenericRead (Sid 5 @(32, 555)))))
Write-Seed 'fuzz_kek_dacl' 'everyone_read' (Join (U8 0) (Acl (Ace 0 0 $GenericAll $System) (Ace 0 0 $GenericAll $Admins) `
            (Ace 0 0 $GenericRead $Everyone)))
Write-Seed 'fuzz_kek_dacl' 'others_write_inherit_only' (Join (U8 3) (Acl (Ace 0 0 $GenericAll $System) `
            (Ace 0 0x08 $FileWriteData $Users) (Ace 1 0 $FileWriteData $Users)))

# ---- fuzz_v2_kdf: two (service, header) pairs ----

$salt = New-Object byte[] 32
for ($i = 0; $i -lt 32; $i++) { $salt[$i] = [byte]$i }
$header = Join ([byte[]]@(2, 1, 0, 0, 1, 0, 0, 0)) $salt
$pairA = Join (U8 8) (Ascii 'myapp.v2') $header
$pairB = Join (U8 9) (Ascii 'myapp.v2x') $header
Write-Seed 'fuzz_v2_kdf' 'two_services' (Join $pairA $pairB)
Write-Seed 'fuzz_v2_kdf' 'same_pair' (Join $pairA $pairA)
Write-Seed 'fuzz_v2_kdf' 'length_boundary' (Join (U8 1) (Ascii 'a') $header (U8 2) (Ascii 'a') ([byte[]]@($header[0])) $header)

Write-Host "seeds written to $(Join-Path $PSScriptRoot 'corpus')"
