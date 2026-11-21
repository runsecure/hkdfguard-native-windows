<#
.SYNOPSIS
Writes the seeds for the five C ABI libFuzzer targets (fuzz_abi.h).

.DESCRIPTION
    powershell -File tests\fuzz\Make-AbiSeeds.ps1 -OutDir <dir>     # writes <dir>\<target>\

These are the memory attacks a caller of a C library tries first - a
capacity one byte short, zero, negative; NULL where a pointer belongs; a
payload cut off inside its header, or with each header byte set to its
extremes; a string that ends early, late or never; a path to a device -
written down so that no run depends on the fuzzer rediscovering them. The
same list, shape for shape, as hkdfguard-native-linux's fuzz/make_seeds.py,
plus what only Windows has: SIDs, file ACLs, device, stream and UNC paths,
and every text encoding of a plaintext key.

About 2,500 small files, so the build generates them (tests/CMakeLists.txt)
rather than checking them in: this script is their source. Payloads can't be
stored (the KEK is made per run), so a seed names "the genuine payload" and
the edits to make to it, as the targets' inputs do. When a target's input
changes shape, change its builder here. Add a seed for every finding, named
for it. Nothing here is secret.

Runs under Windows PowerShell 5.1 and PowerShell 7; needs nothing else.
(Make-Seeds.ps1 writes the checked-in corpora of the two older targets,
fuzz_kek_dacl and fuzz_v2_kdf.)
#>
param([Parameter(Mandatory = $true)][string]$OutDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---- bytes ----

# A byte string from text with C-style escapes: \xNN, \n, \r, \t, \0, \\.
# Every other character is its own byte, so the text must be ASCII.
function B([string]$Text) {
    $out = New-Object System.IO.MemoryStream
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ($c -ne '\') {
            if ([int]$c -gt 127) { throw "B: non-ASCII character in '$Text'; write it as \xNN" }
            $out.WriteByte([byte]$c)
            continue
        }
        $i++
        switch ($Text[$i]) {
            'x' { $out.WriteByte([Convert]::ToByte($Text.Substring($i + 1, 2), 16)); $i += 2 }
            'n' { $out.WriteByte(10) }
            'r' { $out.WriteByte(13) }
            't' { $out.WriteByte(9) }
            '0' { $out.WriteByte(0) }
            '\' { $out.WriteByte(92) }
            default { throw "B: unknown escape \$($Text[$i]) in '$Text'" }
        }
    }
    return , $out.ToArray()
}

# The concatenation of its arguments, each a byte array.
function Join {
    $out = New-Object System.IO.MemoryStream
    foreach ($part in $args) {
        $bytes = [byte[]]$part
        $out.Write($bytes, 0, $bytes.Length)
    }
    return , $out.ToArray()
}

# `Count` copies of one byte.
function Rep([int]$Byte, [int]$Count) {
    $bytes = New-Object byte[] $Count
    for ($i = 0; $i -lt $Count; $i++) { $bytes[$i] = [byte]$Byte }
    return , $bytes
}

# The bytes First, First + 1, ... below End.
function Range([int]$First, [int]$End) {
    $bytes = New-Object byte[] ($End - $First)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [byte]($First + $i) }
    return , $bytes
}

# `Count` copies of a byte string.
function Times([byte[]]$Bytes, [int]$Count) {
    $out = New-Object System.IO.MemoryStream
    for ($i = 0; $i -lt $Count; $i++) { $out.Write($Bytes, 0, $Bytes.Length) }
    return , $out.ToArray()
}

function Slice([byte[]]$Bytes, [int]$Start, [int]$Count) {
    $out = New-Object byte[] $Count
    [Array]::Copy($Bytes, $Start, $out, 0, $Count)
    return , $out
}

function Base64([byte[]]$Bytes) { return , [Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String($Bytes)) }
function Hex([byte[]]$Bytes) { return , [Text.Encoding]::ASCII.GetBytes(([BitConverter]::ToString($Bytes) -replace '-', '').ToLowerInvariant()) }
function Ascii([string]$Text) { return , [Text.Encoding]::ASCII.GetBytes($Text) }
function Text([byte[]]$Bytes) { return [Text.Encoding]::ASCII.GetString($Bytes) }

# ---- the encoding fuzz_abi.h's In reads ----

function U8([int]$N) { return , [byte[]]@($N -band 0xFF) }
function U16([int]$N) { return , [BitConverter]::GetBytes([uint16]$N) }
function I16([int]$N) { return , [BitConverter]::GetBytes([int16]$N) }
function U32([long]$N) { return , [BitConverter]::GetBytes([uint32]$N) }
function Flag([bool]$Value) { if ($Value) { return U8 1 } return U8 0 }

# A byte string: a u16 length, then the bytes.
function Blob([byte[]]$Data) {
    if ($null -eq $Data) { $Data = [byte[]]@() }
    if ($Data.Length -gt 0xFFFF) { throw "Blob: $($Data.Length) bytes" }
    return Join (U16 $Data.Length) $Data
}

# ---- the types fuzz_abi.h shares ----

function Svc([string]$Kind, [byte[]]$Raw) {
    $index = [Array]::IndexOf(@('fuzz', 'upper', 'other', 'raw', 'null'), $Kind)
    if ($index -lt 0) { throw "Svc: $Kind" }
    if ($Kind -eq 'raw') { return Join (U8 $index) (Blob $Raw) }
    return U8 $index
}

function CallB([int]$Cap, [bool]$OutNull = $false, [bool]$OutLenNull = $false) {
    $flags = 0
    if ($OutNull) { $flags = $flags -bor 1 }
    if ($OutLenNull) { $flags = $flags -bor 2 }
    return Join (I16 $Cap) (U8 $flags)
}

function PayloadGenuine { return U8 0 }
function PayloadRaw([byte[]]$Data) { return Join (U8 1) (Blob $Data) }

# $Ops: (offset, xor) pairs. $Truncate: -1 for none.
function PayloadPatched($Ops, [int]$Truncate = -1, [byte[]]$Extend) {
    $Ops = @($Ops)
    if ($Ops.Count -gt 16) { throw "PayloadPatched: $($Ops.Count) patches" }
    $out = Join (U8 2) (U8 $Ops.Count)
    foreach ($op in $Ops) { $out = Join $out (U16 $op[0]) (U8 $op[1]) }
    if ($Truncate -lt 0) { $out = Join $out (Flag $false) } else { $out = Join $out (Flag $true) (U16 $Truncate) }
    return Join $out (Blob $Extend)
}

# Output buffers: (name, capacity, out NULL, out_len NULL). $Exact is the
# size the call needs; the others are wrong whatever it is.
function Calls([int]$Exact) {
    return @(
        , @("cap-exact-$Exact", $Exact, $false, $false)
        , @("cap-one-short-$($Exact - 1)", ($Exact - 1), $false, $false)
        , @("cap-one-over-$($Exact + 1)", ($Exact + 1), $false, $false)
        , @('cap-zero', 0, $false, $false)
        , @('cap-one', 1, $false, $false)
        , @('cap-minus-one', -1, $false, $false)
        , @('cap-most-negative', -32768, $false, $false)
        , @('cap-largest', 32767, $false, $false)
        , @('out-null', $Exact, $true, $false)
        , @('out-len-null', $Exact, $false, $true)
        , @('both-null', $Exact, $true, $true)
        , @('out-null-cap-zero', 0, $true, $false)
        , @('out-null-cap-one', 1, $true, $false)
    )
}

function CapCalls([int[]]$Caps) {
    $out = @()
    foreach ($c in $Caps) { $out += , @("cap-$c", $c, $false, $false) }
    return $out
}

# Strings a caller might pass where a service or a principal belongs.
$HostileStrings = @(
    , @('empty', (B ''))
    , @('one-byte', (B 'a'))
    , @('format-string', (B '%s%s%s%n%x%p'))
    , @('path-traversal', (B '../../../../etc/passwd'))
    , @('path-traversal-windows', (B '..\\..\\..\\Windows\\win.ini'))
    , @('absolute-path', (B 'C:\\Windows\\System32\\config\\SAM'))
    , @('device', (B '\\\\.\\PhysicalDrive0'))
    , @('reserved-name', (B 'CON'))
    , @('stream', (B 'svc:evil'))
    , @('environment', (B '%SystemRoot%'))
    , @('registry', (B 'HKLM\\Software\\Policies\\HkdfGuard'))
    , @('newline', (B 'hkdfguardwin.fuzz\nClassicalMode=1'))
    , @('carriage-return', (B 'hkdfguardwin.fuzz\r\n'))
    , @('high-bytes', (B '\xff\xfe\xfd\xfc'))
    , @('overlong-utf8-nul', (B 'com\xc0\x80fuzz'))
    , @('utf8-bom', (B '\xef\xbb\xbfhkdfguardwin.fuzz'))
    , @('utf16-text', (B 's\0v\0c\0'))
    , @('fullwidth-letters', (B '\xef\xbd\x93\xef\xbd\x96\xef\xbd\x83'))
    , @('space-padded', (B ' hkdfguardwin.fuzz '))
    , @('dot', (B '.'))
    , @('dot-dot', (B '..'))
    , @('leading-dot', (B '.svc'))
    , @('inner-dot-dot', (B 'a..b'))
    , @('trailing-dot', (B 'svc.'))
    , @('underscore', (B 'my_service'))
    , @('hyphen', (B 'my-service'))
    , @('shell', (B '$(id);`id`|id&whoami'))
    , @('quote', (B 'a"]\n[b'))
    , @('control-bytes', (Range 1 32))
    , @('del-and-escape', (B 'a\x7f\x1b[2Jb'))
    , @('sddl', (B 'D:(A;;GA;;;WD)'))
)

# $Genuine: the service the target's KEKs belong to; $Mixed: the same name in
# another mix of cases.
function ServiceStrings([string]$Genuine, [string]$Mixed) {
    $g = Ascii $Genuine
    $out = @()
    foreach ($h in $HostileStrings) { $out += , @($h[0], (Svc 'raw' $h[1])) }
    $out += , @('genuine', (Svc 'fuzz'))
    $out += , @('genuine-other-case', (Svc 'upper'))
    $out += , @('no-kek', (Svc 'other'))
    $out += , @('null', (Svc 'null'))
    # The first NUL ends it: this is the genuine service, whatever follows.
    $out += , @('early-nul-genuine', (Svc 'raw' (Join $g (B '\0.evil'))))
    $out += , @('early-nul-at-start', (Svc 'raw' (Join (B '\0') $g)))
    $out += , @('early-nul-prefix', (Svc 'raw' (Join (Slice $g 0 8) (B '\0') (Slice $g 8 ($g.Length - 8)))))
    $out += , @('len-127', (Svc 'raw' (Rep 0x61 127)))
    $out += , @('len-128-longest', (Svc 'raw' (Rep 0x61 128)))
    $out += , @('len-129-one-over', (Svc 'raw' (Rep 0x61 129)))
    $out += , @('len-130', (Svc 'raw' (Rep 0x61 130)))
    $out += , @('len-256', (Svc 'raw' (Rep 0x61 256)))
    $out += , @('len-1500', (Svc 'raw' (Rep 0x61 1500)))
    $out += , @('genuine-then-junk', (Svc 'raw' (Join $g (B 'x'))))
    $out += , @('genuine-mixed-case', (Svc 'raw' (Ascii $Mixed)))
    return $out
}

# A payload is 132 bytes: version, provider, two reserved, key id (4), salt
# (32) - the 40-byte header - then nonce (12), ciphertext (32), tag (16) and
# the KEK fingerprint (32).
$PayloadLen = 132
$HeaderLen = 40

function Header([int]$Version = 2, [int]$Provider = 2, [int]$Reserved0 = 0, [int]$Reserved1 = 0, [long]$KeyId = 1) {
    return Join (U8 $Version) (U8 $Provider) (U8 $Reserved0) (U8 $Reserved1) (U32 $KeyId)
}

# 132 bytes with the given header fields and arbitrary contents.
function Shaped([int]$Version = 2, [int]$Provider = 2, [int]$Reserved0 = 0, [int]$Reserved1 = 0, [long]$KeyId = 1) {
    return Join (Header $Version $Provider $Reserved0 $Reserved1 $KeyId) (Range 0 ($PayloadLen - 8))
}

# Edits to a genuine payload: (name, byte flips, truncate to or -1, bytes
# appended).
function PayloadEdits {
    $edits = @()
    # Every byte of the header at its extremes, then the first and last byte
    # of each field after it.
    foreach ($offset in (@(0..($HeaderLen - 1)) + @(40, 51, 52, 83, 84, 99, 100, 131))) {
        foreach ($x in @(, @('ff', 0xFF)) + @(, @('80', 0x80)) + @(, @('01', 0x01))) {
            $edits += , @(("byte-{0:000}-xor-{1}" -f $offset, $x[0]), @(, @($offset, $x[1])), -1, [byte[]]@())
        }
    }
    $allFf = @()
    foreach ($o in 0..15) { $allFf += , @($o, 0xFF) }
    $edits += , @('header-all-ff', $allFf, -1, [byte[]]@())
    $edits += , @('first-and-last-field', @(@(8, 0x01), @(131, 0x01)), -1, [byte[]]@())
    foreach ($n in @(0, 1, 2, 3, 4, 5, 7, 8, 9, 16, 31, 32, 33, 39, 40, 41, 51, 52, 53, 64, 83, 84, 85, 99, 100, 101, 130, 131)) {
        $edits += , @(("truncated-to-{0:000}" -f $n), @(), $n, [byte[]]@())
    }
    $edits += , @('last-byte-flipped', @(, @(0xFFFF, 0x01)), -1, [byte[]]@())  # offsets wrap round the payload
    $edits += , @('extended-by-one-zero', @(), -1, (B '\0'))
    $edits += , @('extended-by-one-ff', @(), -1, (B '\xff'))
    $edits += , @('extended-by-16-bytes', @(), -1, (Rep 0xA5 16))
    $edits += , @('extended-by-a-second-header', @(), -1, (Join (Header) (Rep 0 32)))
    $edits += , @('extended-by-a-second-payload', @(), -1, (Join (Header) (Rep 0 ($PayloadLen - 8))))
    $edits += , @('extended-by-1500-bytes', @(), -1, (Rep 0xFF 1500))
    $edits += , @('truncated-then-refilled', @(), 20, (Rep 0xFF 200))
    $edits += , @('truncated-then-refilled-to-132', @(), 40, (Rep 0xFF 92))
    return $edits
}

$RawPayloads = @(
    , @('empty', (B ''))
    , @('one-zero', (B '\0'))
    , @('one-ff', (B '\xff'))
    , @('zeros-64', (Rep 0 64))
    , @('zeros-131', (Rep 0 131))
    , @('zeros-132', (Rep 0 132))
    , @('zeros-133', (Rep 0 133))
    , @('ff-131', (Rep 0xFF 131))
    , @('ff-132', (Rep 0xFF 132))
    , @('ff-133', (Rep 0xFF 133))
    , @('ff-1500', (Rep 0xFF 1500))
    , @('ascending', (Range 0 256))
    , @('well-formed-v1', (Shaped -Version 1))
    , @('well-formed-v2', (Shaped -Version 2))
    , @('well-formed-tpm', (Shaped -Provider 1))
    , @('version-0', (Shaped -Version 0))
    , @('version-3', (Shaped -Version 3))
    , @('version-255', (Shaped -Version 255))
    , @('provider-0', (Shaped -Provider 0))
    , @('provider-3', (Shaped -Provider 3))
    , @('provider-255', (Shaped -Provider 255))
    , @('reserved-first', (Shaped -Reserved0 1))
    , @('reserved-second', (Shaped -Reserved1 0x80))
    , @('key-id-0', (Shaped -KeyId 0))
    , @('key-id-2', (Shaped -KeyId 2))
    , @('key-id-big-endian-1', (Shaped -KeyId 0x01000000))
    , @('key-id-max', (Shaped -KeyId 4294967295))
    , @('key-id-signed-min', (Shaped -KeyId 2147483648))
    , @('header-only', (Join (Header) (Rep 0 32)))
    , @('text', (B '-----BEGIN HKDFGUARD KEY-----\r\n'))
    , @('base64-of-a-payload', (Base64 (Shaped)))
)

# Every seed under each payload version: the input's first byte.
function BothVersions($Seeds) {
    $out = [ordered]@{}
    foreach ($name in $Seeds.Keys) {
        $out["v2-$name"] = Join (U8 0) $Seeds[$name]
        $out["v1-$name"] = Join (U8 1) $Seeds[$name]
    }
    return $out
}

# ---- the targets ----

function Seeds-UnwrapDek {
    $good = CallB 32
    $seeds = [ordered]@{}
    foreach ($c in (Calls 32)) {
        $buffer = CallB $c[1] $c[2] $c[3]
        $seeds["buffer-$($c[0])"] = Join (Svc 'fuzz') (PayloadGenuine) $buffer
        $seeds["buffer-$($c[0])-corrupt-payload"] = Join (Svc 'fuzz') (PayloadPatched @(, @(60, 1))) $buffer
        $seeds["buffer-$($c[0])-bad-service"] = Join (Svc 'raw' (B '..')) (PayloadGenuine) $buffer
    }
    foreach ($s in (ServiceStrings 'hkdfguardwin.fuzz.unwrap' 'Hkdfguardwin.Fuzz.Unwrap')) {
        $seeds["service-$($s[0])"] = Join $s[1] (PayloadGenuine) $good
    }
    foreach ($e in (PayloadEdits)) {
        $seeds["payload-$($e[0])"] = Join (Svc 'fuzz') (PayloadPatched $e[1] $e[2] $e[3]) $good
    }
    foreach ($r in $RawPayloads) {
        $seeds["raw-$($r[0])"] = Join (Svc 'fuzz') (PayloadRaw $r[1]) $good
    }
    $seeds['everything-wrong'] = Join (Svc 'null') (PayloadRaw (B '')) (CallB -1 $true $true)
    return BothVersions $seeds
}

$Sids = @(
    , @('system', (B 'S-1-5-18'))
    , @('administrators', (B 'S-1-5-32-544'))
    , @('users', (B 'S-1-5-32-545'))
    , @('everyone', (B 'S-1-1-0'))
    , @('authenticated-users', (B 'S-1-5-11'))
    , @('trusted-installer', (B 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'))
    , @('a-user', (B 'S-1-5-21-1-2-3-1001'))
    , @('lowercase', (B 's-1-5-18'))
    , @('sddl-alias-ba', (B 'BA'))
    , @('sddl-alias-wd', (B 'WD'))
    , @('sddl-alias-sy', (B 'SY'))
    , @('account-name', (B 'Administrators'))
    , @('authority-only', (B 'S-1-5'))
    , @('no-authority', (B 'S-1'))
    , @('revision-2', (B 'S-2-5-18'))
    , @('trailing-hyphen', (B 'S-1-5-'))
    , @('rid-u32-max', (B 'S-1-5-4294967295'))
    , @('rid-u32-overflow', (B 'S-1-5-4294967296'))
    , @('rid-huge', (B 'S-1-5-99999999999999999999'))
    , @('rid-negative', (B 'S-1-5--1'))
    , @('rid-plus', (B 'S-1-5-+18'))
    , @('rid-hex', (B 'S-1-0x5-0x12'))
    , @('authority-u48-max', (B 'S-1-281474976710655-1'))
    , @('authority-u48-overflow', (B 'S-1-281474976710656-1'))
    , @('sub-authorities-15', (Join (B 'S-1-5') (Times (B '-1') 15)))
    , @('sub-authorities-16', (Join (B 'S-1-5') (Times (B '-1') 16)))
    , @('leading-space', (B ' S-1-5-18'))
    , @('trailing-space', (B 'S-1-5-18 '))
    , @('trailing-newline', (B 'S-1-5-18\n'))
    , @('early-nul', (B 'S-1-5-18\0-544'))
    , @('empty', (B ''))
    , @('len-255-longest', (Join (B 'S-1-5-') (Rep 0x31 249)))
    , @('len-256-one-over', (Join (B 'S-1-5-') (Rep 0x31 250)))
    , @('len-1500', (Join (B 'S-1-5-') (Rep 0x31 1494)))
    , @('unicode-digits', (B 'S-1-5-\xd9\xa1\xd9\xa8'))
    , @('format-string', (B '%s%n'))
    , @('sddl', (B 'O:BAD:(A;;GA;;;WD)'))
)

function Seeds-WrapRoundTrip {
    function Wrap([byte[]]$Dek, [bool]$DekNull = $false) { return Join (U8 0) (Blob $Dek) (Flag $DekNull) }
    function Exists([bool]$OutNull) { return Join (U8 2) (Flag $OutNull) }
    function Model([bool]$ModelNull, [bool]$MayWriteNull) { return Join (U8 4) (Flag $ModelNull) (Flag $MayWriteNull) }
    function Principal([byte[]]$Sid, [bool]$OutNull = $false) { return Join (U8 5) (Blob $Sid) (Flag $OutNull) }
    $generate = U8 1
    $fingerprint = U8 3

    $svc = Svc 'fuzz'
    $big = CallB 1024
    $dek = Range 0x40 0x60
    $seeds = [ordered]@{}
    foreach ($n in @(0, 1, 16, 31, 32, 33, 48, 64, 132, 256, 1500)) {
        $seeds[("wrap-dek-len-{0:0000}" -f $n)] = Join $svc (Wrap (Rep 0x5A $n)) $big
        $seeds[("wrap-dek-len-{0:0000}-no-buffer" -f $n)] = Join $svc (Wrap (Rep 0x5A $n)) (CallB 0 $true $false)
    }
    $seeds['wrap-dek-null'] = Join $svc (Wrap $dek $true) $big
    $seeds['wrap-dek-null-and-empty'] = Join $svc (Wrap (B '') $true) $big
    $seeds['wrap-dek-all-zero'] = Join $svc (Wrap (Rep 0 32)) $big
    $seeds['wrap-dek-all-ff'] = Join $svc (Wrap (Rep 0xFF 32)) $big
    foreach ($c in ((Calls 132) + (CapCalls @(32, 40, 64, 100, 128, 130, 134, 255, 256, 1024)))) {
        $buffer = CallB $c[1] $c[2] $c[3]
        $seeds["wrap-buffer-$($c[0])"] = Join $svc (Wrap $dek) $buffer
        $seeds["generate-buffer-$($c[0])"] = Join $svc $generate $buffer
        $seeds["wrap-buffer-$($c[0])-no-kek"] = Join (Svc 'other') (Wrap $dek) $buffer
    }
    foreach ($c in (Calls 32)) {
        $buffer = CallB $c[1] $c[2] $c[3]
        $seeds["fingerprint-buffer-$($c[0])"] = Join $svc $fingerprint $buffer
        $seeds["fingerprint-buffer-$($c[0])-no-kek"] = Join (Svc 'other') $fingerprint $buffer
    }
    foreach ($s in (ServiceStrings 'hkdfguardwin.fuzz.wrap' 'Hkdfguardwin.Fuzz.Wrap')) {
        $seeds["wrap-service-$($s[0])"] = Join $s[1] (Wrap $dek) $big
        $seeds["generate-service-$($s[0])"] = Join $s[1] $generate $big
        $seeds["exists-service-$($s[0])"] = Join $s[1] (Exists $false)
        $seeds["fingerprint-service-$($s[0])"] = Join $s[1] $fingerprint (CallB 32)
    }
    $seeds['exists-out-null'] = Join $svc (Exists $true)
    $seeds['exists-everything-null'] = Join (Svc 'null') (Exists $true)
    foreach ($m in @($false, $true)) {
        foreach ($w in @($false, $true)) {
            $seeds["security-model-null-$([int]$m)$([int]$w)"] = Join $svc (Model $m $w)
        }
    }
    foreach ($s in $Sids) { $seeds["principal-$($s[0])"] = Join $svc (Principal $s[1]) }
    $seeds['principal-out-null'] = Join $svc (Principal (B 'S-1-5-18') $true)
    return BothVersions $seeds
}

$Dek = Range 0x40 0x60
$DekHex = Hex $Dek
$B64 = Base64 $Dek                        # 44 characters, the last '='
$Specials = Times (B '\xfb\xff') 16       # 32 bytes whose base64 is all '+' and '/'
$B64Specials = Base64 $Specials
$B64Url = Ascii ((Text $B64Specials).Replace('+', '-').Replace('/', '_'))
$PlaintextKeys = @(
    , @('raw-32', $Dek)
    , @('raw-32-lf', (Join $Dek (B '\n')))
    , @('raw-32-crlf', (Join $Dek (B '\r\n')))
    , @('raw-32-cr', (Join $Dek (B '\r')))
    , @('raw-32-two-lf', (Join $Dek (B '\n\n')))
    , @('raw-31', (Slice $Dek 0 31))
    , @('raw-33', (Join $Dek (B '\0')))
    , @('raw-32-of-whitespace', (Rep 0x20 32))
    , @('hex-lower', $DekHex)
    , @('hex-upper', (Ascii (Text $DekHex).ToUpperInvariant()))
    , @('hex-lf', (Join $DekHex (B '\n')))
    , @('hex-crlf', (Join $DekHex (B '\r\n')))
    , @('hex-padded-with-spaces', (Join (B '  ') $DekHex (B '  \r\n')))
    , @('hex-63', (Slice $DekHex 0 63))
    , @('hex-65', (Join $DekHex (B '0')))
    , @('hex-with-0x', (Join (B '0x') $DekHex))
    , @('hex-one-bad-digit', (Join (Slice $DekHex 0 63) (B 'g')))
    , @('base64', $B64)
    , @('base64-lf', (Join $B64 (B '\n')))
    , @('base64-crlf', (Join $B64 (B '\r\n')))
    , @('base64-unpadded', (Slice $B64 0 43))
    , @('base64-url', $B64Url)
    , @('base64-url-unpadded', (Slice $B64Url 0 43))
    , @('base64-standard-specials', $B64Specials)
    , @('base64-mixed-alphabets', (Join (B '-') (Slice $B64Specials 1 43)))
    , @('base64-two-pads', (Join (Slice $B64 0 43) (B '==')))
    , @('base64-pad-inside', (Join (Slice $B64 0 20) (B '=') (Slice $B64 21 23)))
    , @('base64-non-canonical-last', (Join (Slice $B64 0 42) (B 'B=')))
    , @('base64-of-31', (Base64 (Slice $Dek 0 31)))
    , @('base64-of-33', (Base64 (Join $Dek (B '\0'))))
    , @('base64-utf8-bom', (Join (B '\xef\xbb\xbf') $B64))
    , @('base64-utf16', (Join (B '\xff\xfe') ([Text.Encoding]::Unicode.GetBytes((Text $B64)))))
    , @('base64-wrapped-lines', (Join (Slice $B64 0 22) (B '\r\n') (Slice $B64 22 22)))
    , @('pem', (Join (B '-----BEGIN KEY-----\n') $B64 (B '\n-----END KEY-----\n')))
    , @('only-whitespace', (Times (B ' \t\r\n') 10))
)

# fuzz_open_file.cpp's kAcls, in order.
$Acls = @('owner-only', 'users-read', 'users-full', 'everyone-write', 'authenticated-write-dac', 'authenticated-take-ownership',
    'everyone-read', 'inherited')

# Paths a caller - or whoever chooses the caller's configuration - might
# name. None is a key file; several must not even be opened.
$Paths = @(
    , @('empty', (B ''))
    # Valid UTF-8 that Windows can't resolve to a full path: INVALID_ARGUMENT.
    , @('one-space', (B ' '))
    , @('only-spaces-and-dots', (B ' . . '))
    , @('drive-root', (B 'C:\\'))
    , @('drive-only', (B 'C:'))
    , @('drive-relative', (B 'C:key.bin'))
    , @('relative', (B 'key.bin'))
    , @('dot', (B '.'))
    , @('dot-dot', (B '..'))
    , @('climb', (Join (Times (B '..\\') 40) (B 'Windows\\win.ini')))
    , @('climb-inside', (B 'C:\\HkdfGuardKeys\\..\\Windows\\win.ini'))
    , @('forward-slashes', (B 'C:/Windows/win.ini'))
    , @('backslashes', (Rep 0x5C 300))
    , @('root-relative', (B '\\Windows\\win.ini'))
    , @('win-ini', (B 'C:\\Windows\\win.ini'))
    , @('sam', (B 'C:\\Windows\\System32\\config\\SAM'))
    , @('pagefile', (B 'C:\\pagefile.sys'))
    , @('a-directory', (B 'C:\\Windows'))
    , @('trailing-backslash', (B 'C:\\Windows\\win.ini\\'))
    , @('trailing-dot', (B 'C:\\Windows\\win.ini.'))
    , @('trailing-space', (B 'C:\\Windows\\win.ini '))
    , @('short-name', (B 'C:\\PROGRA~1\\key.bin'))
    , @('stream', (B 'C:\\Windows\\win.ini::$DATA'))
    , @('named-stream', (B 'C:\\Windows\\win.ini:evil'))
    , @('directory-stream', (B 'C:\\Windows::$INDEX_ALLOCATION'))
    , @('device-nul', (B 'NUL'))
    , @('device-con', (B 'CON'))
    , @('device-com1', (B 'COM1'))
    , @('device-nul-in-folder', (B 'C:\\Windows\\NUL'))
    , @('device-conin', (B 'CONIN$'))
    , @('device-namespace-nul', (B '\\\\.\\NUL'))
    , @('device-physical-drive', (B '\\\\.\\PhysicalDrive0'))
    , @('device-volume', (B '\\\\.\\C:'))
    , @('device-pipe', (B '\\\\.\\pipe\\hkdfguard'))
    , @('device-mailslot', (B '\\\\.\\mailslot\\hkdfguard'))
    , @('global-root', (B '\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\Windows\\win.ini'))
    , @('extended-prefix', (B '\\\\?\\C:\\Windows\\win.ini'))
    , @('extended-unc', (B '\\\\?\\UNC\\localhost\\C$\\Windows\\win.ini'))
    , @('nt-prefix', (B '\\??\\C:\\Windows\\win.ini'))
    , @('unc', (B '\\\\server\\share\\key.bin'))
    , @('unc-localhost', (B '\\\\localhost\\C$\\Windows\\win.ini'))
    , @('unc-loopback', (B '\\\\127.0.0.1\\C$\\key.bin'))
    , @('unc-webdav', (B '\\\\server@80\\share\\key.bin'))
    , @('volume-guid', (B '\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\key.bin'))
    , @('no-such-drive', (B 'Q:\\key.bin'))
    , @('early-nul', (B 'C:\\Windows\\win.ini\0.key'))
    , @('early-nul-at-start', (B '\0C:\\Windows\\win.ini'))
    , @('high-bytes', (B 'C:\\\xff\xfe\\\xfd'))
    , @('overlong-utf8-backslash', (B 'C:\xc1\x9cWindows'))
    , @('lone-surrogate', (B 'C:\\\xed\xa0\x80\\key.bin'))
    , @('newline', (B 'C:\\HkdfGuardKeys\\key\n.bin'))
    , @('wildcard', (B 'C:\\Windows\\*.ini'))
    , @('question-mark', (B 'C:\\Windows\\win.in?'))
    , @('pipe-and-quote', (B 'C:\\Windows\\"|<>'))
    , @('environment', (B '%SystemRoot%\\win.ini'))
    , @('component-255', (Join (B 'C:\\') (Rep 0x61 255)))
    , @('component-256', (Join (B 'C:\\') (Rep 0x61 256)))
    , @('len-260', (Join (B 'C:\\') (Times (B 'a\\') 128) (B 'a')))
    , @('len-1500', (Join (B 'C:\\') (Times (B 'a\\') 748) (B 'a')))
    , @('len-1500-one-component', (Join (B 'C:\\') (Rep 0x61 1497)))
    , @('len-4000', (Join (B 'C:\\') (Times (B 'ab\\') 1332)))
    # C:\<Cyrillic "keys">\<Cyrillic "key">.bin, in UTF-8
    , @('unicode', (B 'C:\\\xd0\x9a\xd0\xbb\xd1\x8e\xd1\x87\xd0\xb8\\\xd0\xba\xd0\xbb\xd1\x8e\xd1\x87.bin'))
    , @('uri', (B 'file:///C:/Windows/win.ini'))
    , @('format-string', (B 'C:\\%s%n%x'))
)

function Seeds-OpenFile {
    function Content([byte[]]$Data, [string]$Acl, [bool]$GenuinePrefix) {
        return Join (U8 0) (Blob $Data) (U8 ([Array]::IndexOf($Acls, $Acl))) (Flag $GenuinePrefix)
    }
    function PathInput([byte[]]$Path) { return Join (U8 1) (Blob $Path) }

    $big = CallB 1024
    $junk = Rep 0xFF 200
    $seeds = [ordered]@{}
    foreach ($acl in $Acls) {
        $seeds["genuine-acl-$acl"] = Join (Content (B '') $acl $true) $big
        $seeds["not-a-key-file-acl-$acl"] = Join (Content $junk $acl $false) $big
        $seeds["plaintext-key-acl-$acl"] = Join (Content $Dek $acl $false) $big
    }
    foreach ($c in ((Calls 132) + (CapCalls @(16, 32, 40, 64, 100, 128, 130, 134, 256)))) {
        $buffer = CallB $c[1] $c[2] $c[3]
        $seeds["buffer-$($c[0])"] = Join (Content (B '') 'owner-only' $true) $buffer
        $seeds["buffer-$($c[0])-not-a-key-file"] = Join (Content $junk 'owner-only' $false) $buffer
        $seeds["buffer-$($c[0])-plaintext-key"] = Join (Content $Dek 'owner-only' $false) $buffer
    }
    $extras = @(
        , @('one-zero', (B '\0'))
        , @('one-ff', (B '\xff'))
        , @('a-newline', (B '\n'))
        , @('crlf', (B '\r\n'))
        , @('1500-bytes', (Rep 0xFF 1500))
    )
    foreach ($e in $extras) {
        $seeds["genuine-then-$($e[0])"] = Join (Content $e[1] 'owner-only' $true) $big
        $seeds["genuine-then-$($e[0])-small-buffer"] = Join (Content $e[1] 'owner-only' $true) (CallB 64)
    }
    foreach ($r in $RawPayloads) {
        $seeds["content-$($r[0])"] = Join (Content $r[1] 'owner-only' $false) $big
        $seeds["content-$($r[0])-small-buffer"] = Join (Content $r[1] 'owner-only' $false) (CallB 64)
    }
    foreach ($k in $PlaintextKeys) { $seeds["plaintext-$($k[0])"] = Join (Content $k[1] 'owner-only' $false) $big }
    foreach ($p in $Paths) {
        $seeds["path-$($p[0])"] = Join (PathInput $p[1]) $big
        $seeds["path-$($p[0])-small-buffer"] = Join (PathInput $p[1]) (CallB 64)
    }
    $seeds['path-empty-everything-null'] = Join (PathInput (B '')) (CallB -1 $true $true)
    return BothVersions $seeds
}

function Seeds-StringBounds {
    # fuzz_string_bounds.cpp's Arg, in order.
    $argNames = @('service-create-kek', 'service-exists', 'service-fingerprint', 'service-wrap', 'service-unwrap', 'service-generate',
        'path-open-file', 'principal')

    # $Head $null: the genuine string.
    function EarlyNul($Head, [byte[]]$Tail) {
        if ($null -eq $Head) { return Join (U8 3) (Flag $false) (Blob $Tail) }
        return Join (U8 3) (Flag $true) (Blob ([byte[]]$Head)) (Blob $Tail)
    }

    $fills = @(, @('a', 0x61)) + @(, @('ff', 0xFF)) + @(, @('01', 0x01)) + @(, @('backslash', 0x5C)) + @(, @('dot', 0x2E)) +
        @(, @('digit', 0x31))
    $seeds = [ordered]@{}
    for ($index = 0; $index -lt $argNames.Count; $index++) {
        $name = $argNames[$index]
        $arg = U8 $index
        foreach ($f in $fills) {
            $seeds["$name-unterminated-fill-$($f[0])"] = Join $arg (U8 0) (U8 $f[1])
            $seeds["$name-longest-fill-$($f[0])"] = Join $arg (U8 1) (U8 $f[1])
            $seeds["$name-one-over-the-limit-fill-$($f[0])"] = Join $arg (U8 2) (U8 $f[1])
        }
        $seeds["$name-genuine-nul-is-last-byte"] = Join $arg (EarlyNul $null (B ''))
        $seeds["$name-genuine-then-nul-then-junk"] = Join $arg (EarlyNul $null (B '.evil'))
        $seeds["$name-genuine-then-nul-then-1500-bytes"] = Join $arg (EarlyNul $null (Rep 0xFF 1500))
        $seeds["$name-genuine-then-nul-then-another-string"] = Join $arg (EarlyNul $null (B 'hkdfguardwin.fuzz.other\0'))
        $seeds["$name-empty-then-junk"] = Join $arg (EarlyNul (B '') (B 'hkdfguardwin.fuzz.strings'))
        $seeds["$name-one-byte-then-junk"] = Join $arg (EarlyNul (B 'a') (B 'bc'))
        foreach ($h in $HostileStrings[2..13]) {
            $seeds["$name-$($h[0])-then-nul"] = Join $arg (EarlyNul $h[1] (B '\xff'))
        }
    }
    return BothVersions $seeds
}

function Seeds-ApiThreads {
    function Exists([bool]$Other) { return Join (U8 1) (Flag $Other) }
    function WrapUnwrap([int]$Byte, [bool]$Upper = $false) { return Join (U8 3) (U8 $Byte) (Flag $Upper) }
    function UnwrapGenuine([int]$Cap) { return Join (U8 5) (I16 $Cap) }
    function UnwrapPatched([int]$Offset, [int]$Xor) { return Join (U8 6) (U16 $Offset) (U8 $Xor) }
    function OpenFile([int]$Cap) { return Join (U8 7) (I16 $Cap) }
    $create = U8 0
    $fingerprint = U8 2
    $generate = U8 4
    $wrapOther = U8 8
    $principal = U8 9

    # $Plans: one list of operations per thread.
    function Threads($Plans) {
        $Plans = @($Plans)
        if ($Plans.Count -lt 1 -or $Plans.Count -gt 4) { throw "Threads: $($Plans.Count) threads" }
        $out = U8 ($Plans.Count - 1)
        foreach ($plan in $Plans) {
            $plan = @($plan)
            if ($plan.Count -gt 16) { throw "Threads: $($plan.Count) operations" }
            $out = Join $out (U8 $plan.Count)
            foreach ($op in $plan) { $out = Join $out $op }
        }
        return , $out
    }
    # `Count` copies of a list of operations, as one list.
    function Repeat($Ops, [int]$Count) {
        $out = @()
        for ($i = 0; $i -lt $Count; $i++) { foreach ($op in @($Ops)) { $out += , $op } }
        return , $out
    }
    function Ops { return , @($args) }

    $everything = Ops $create (Exists $false) (Exists $true) $fingerprint (WrapUnwrap 1) (WrapUnwrap 2 $true) $generate `
        (UnwrapGenuine 32) (UnwrapGenuine 31) (UnwrapPatched 60 1) (OpenFile 1024) (OpenFile 16) $wrapOther $principal (UnwrapGenuine -1)
    $reversed = @($everything); [Array]::Reverse($reversed)
    $rotated = @($everything[5..14]) + @($everything[0..4])
    $everyOther = @(); for ($i = 0; $i -lt $everything.Count; $i += 2) { $everyOther += , $everything[$i] }

    $seeds = [ordered]@{}
    $seeds['every-op-on-four-threads'] = Threads @($everything, $reversed, $rotated, $everyOther)
    $seeds['create-kek-on-four-threads'] = Threads @((Repeat (Ops $create) 12), (Repeat (Ops $create) 12), (Repeat (Ops $create) 12),
        (Repeat (Ops $create) 12))
    $seeds['create-kek-against-wrap'] = Threads @((Repeat (Ops $create) 12), (Repeat (Ops (WrapUnwrap 3)) 12),
        (Repeat (Ops $create $generate) 6), (Repeat (Ops (WrapUnwrap 4 $true)) 12))
    $seeds['distinct-deks-on-four-threads'] = Threads @((Repeat (Ops (WrapUnwrap 0x11)) 16), (Repeat (Ops (WrapUnwrap 0x22)) 16),
        (Repeat (Ops (WrapUnwrap 0x33)) 16), (Repeat (Ops (WrapUnwrap 0x44)) 16))
    $corruptHeader = @(); foreach ($o in 0..15) { $corruptHeader += , (UnwrapPatched $o 0xFF) }
    $seeds['unwrap-genuine-against-corrupt'] = Threads @((Repeat (Ops (UnwrapGenuine 32)) 16), $corruptHeader,
        (Repeat (Ops (UnwrapGenuine 0) (UnwrapGenuine -1)) 8))
    $everyField = @()
    foreach ($t in 0..3) {
        $plan = @(); for ($o = 0; $o -lt 128; $o += 8) { $plan += , (UnwrapPatched ($o + $t) 0x80) }
        $everyField += , $plan
    }
    $seeds['corrupt-every-field-on-four-threads'] = Threads $everyField
    $small = @()
    foreach ($c in @(0, 1, 31, -1)) { $small += , (Repeat (Ops (UnwrapGenuine $c) (OpenFile $c)) 8) }
    $seeds['small-buffers-on-four-threads'] = Threads $small
    $seeds['open-file-against-wrap'] = Threads @((Repeat (Ops (OpenFile 1024)) 16), (Repeat (Ops (WrapUnwrap 5)) 16),
        (Repeat (Ops (OpenFile 131) (OpenFile 132)) 8))
    $seeds['fingerprint-and-exists-against-generate'] = Threads @((Repeat (Ops $fingerprint (Exists $false) (Exists $true)) 5),
        (Repeat (Ops $generate) 16), (Repeat (Ops $wrapOther) 16))
    $seeds['two-threads'] = Threads @((Repeat (Ops (WrapUnwrap 6)) 8), (Repeat (Ops (WrapUnwrap 7)) 8))
    $seeds['one-thread'] = Threads @(, $everything)
    return BothVersions $seeds
}

# The targets' ctest runs use -max_len=4096: a longer input is never run.
$MaxSeedLen = 4096

$targets = [ordered]@{
    'fuzz_unwrap_dek'      = { Seeds-UnwrapDek }
    'fuzz_wrap_round_trip' = { Seeds-WrapRoundTrip }
    'fuzz_open_file'       = { Seeds-OpenFile }
    'fuzz_string_bounds'   = { Seeds-StringBounds }
    'fuzz_api_threads'     = { Seeds-ApiThreads }
}

$root = [IO.Path]::GetFullPath($OutDir)
$count = 0
foreach ($target in $targets.Keys) {
    $directory = Join-Path $root $target
    if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force }
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $seeds = & $targets[$target]
    foreach ($name in $seeds.Keys) {
        $data = [byte[]]$seeds[$name]
        if ($data.Length -gt $MaxSeedLen) { throw "$target/${name}: $($data.Length) bytes, over -max_len" }
        [IO.File]::WriteAllBytes((Join-Path $directory $name), $data)
        $count++
    }
}
Write-Host "${root}: wrote $count seeds"
