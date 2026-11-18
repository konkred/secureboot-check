<#
    Run-Tests.ps1 - Selbsttest des Werkzeugkastens, ohne Firmware anzufassen.

    Prueft:
      1. Alle Skripte lassen sich fehlerfrei parsen, sind reines ASCII und haben CRLF.
      2. Die Parser- und Entscheidungsfunktionen mit kuenstlich erzeugten Daten
         (gueltige und kaputte Signaturlisten, altes Dateiformat, PCA-2011-Sperre).
      3. Optional echte Dateien unter tests\fixtures\<PC>\ (siehe Testdateien_sammeln.cmd):
         jede Microsoft-Datei muss erkannt werden, DBXUpdate2024 muss immer abgelehnt werden.

    Braucht keine Administratorrechte. Es wird nichts geschrieben ausser der Bildschirmausgabe.
#>
param([switch]$NoPause)

$ErrorActionPreference = 'Stop'
$root    = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$testDir = Split-Path -Parent $PSCommandPath
Add-Type -AssemblyName System.Security

$script:pass = 0; $script:fail = 0
function Check([string]$Name, [bool]$Cond, [string]$Detail = '') {
    if ($Cond) { $script:pass++; Write-Host "  [OK]   $Name" -ForegroundColor Green }
    else       { $script:fail++; Write-Host "  [!!]   $Name  $Detail" -ForegroundColor Red }
}
function Head([string]$t) { Write-Host ""; Write-Host "== $t" -ForegroundColor Cyan }

function Get-FunctionTexts([string]$Path, [string[]]$Names) {
    $tok = $null; $err = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tok, [ref]$err)
    $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) |
        Where-Object { $Names -contains $_.Name } | ForEach-Object { $_.Extent.Text }
}

# ------------------------------------------------------------------ Hilfen fuer Testdaten
$X509Guid   = [Guid]'a5c059a1-94e4-4aa7-87b5-ab155c2bf072'
$Sha256Guid = [Guid]'c1c41626-504c-4092-aca9-41f936934328'
$Pkcs7Guid  = [Guid]'4aafd29d-68df-49ee-8aa9-347d375665a7'
$MsOwner    = [Guid]'77fa9abd-0359-4d32-bd60-28f4e78f784b'
$DbGuid     = [Guid]'d719b2cb-3d3a-4596-a3bc-dad00e67656f'

function Cat-Bytes { param([object[]]$Parts) $l = New-Object System.Collections.Generic.List[byte]; foreach ($p in $Parts) { if ($p) { $l.AddRange([byte[]]$p) } }; ,$l.ToArray() }
function New-Esl([Guid]$Type, [object[]]$Entries) {
    # Eine EFI_SIGNATURE_LIST, alle Eintraege gleich gross
    $data = [byte[]]$Entries[0]
    $sigSize = 16 + $data.Length
    $listSize = 28 + $sigSize * $Entries.Count
    $parts = @($Type.ToByteArray(), [BitConverter]::GetBytes([uint32]$listSize), [BitConverter]::GetBytes([uint32]0), [BitConverter]::GetBytes([uint32]$sigSize))
    foreach ($e in $Entries) { $parts += ,$MsOwner.ToByteArray(); $parts += ,([byte[]]$e) }
    Cat-Bytes $parts
}
function New-HashEsl([int]$Count) {
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $e = @(); for ($i = 0; $i -lt $Count; $i++) { $h = New-Object byte[] 32; $rng.GetBytes($h); $e += ,$h }
    New-Esl $Sha256Guid $e
}
function New-TestCert([string]$Subject) {
    try {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest ($Subject, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $c = $req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddYears(1))
        New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$c.RawData)
    } catch { $null }
}
function New-AuthFile([string]$Path, [byte[]]$Content, [switch]$Wrapped) {
    # EFI_VARIABLE_AUTHENTICATION_2 mit Dummy-Signatur; -Wrapped = aelteres Format mit Variablenkopf
    $time = New-Object byte[] 16
    [BitConverter]::GetBytes([uint16]2024).CopyTo($time, 0); $time[2] = 5; $time[3] = 14
    $sig = New-Object byte[] 64
    $dwLength = 4 + 2 + 2 + 16 + $sig.Length
    $hdr = Cat-Bytes @($time, [BitConverter]::GetBytes([uint32]$dwLength), [BitConverter]::GetBytes([uint16]0x0200), [BitConverter]::GetBytes([uint16]0x0EF1), $Pkcs7Guid.ToByteArray(), $sig)
    if ($Wrapped) {
        $Content = Cat-Bytes @([Text.Encoding]::Unicode.GetBytes("dbx`0"), $DbGuid.ToByteArray(), [BitConverter]::GetBytes([uint32]0x27), $time, $Content)
    }
    [IO.File]::WriteAllBytes($Path, (Cat-Bytes @($hdr, $Content)))
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("sbtest_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

# ------------------------------------------------------------------ 1. Dateien
Head "Dateien: Syntax, ASCII, CRLF"
$files = @(Get-ChildItem $root -File | Where-Object { $_.Extension -in '.ps1','.cmd' }) + @(Get-ChildItem $testDir -File | Where-Object { $_.Extension -in '.ps1','.cmd' })
foreach ($f in $files) {
    $b = [IO.File]::ReadAllBytes($f.FullName)
    Check "$($f.Name): nur ASCII" (-not ($b | Where-Object { $_ -gt 127 }))
    $lf = 0; $bad = 0
    for ($i = 0; $i -lt $b.Length; $i++) { if ($b[$i] -eq 10) { $lf++; if ($i -eq 0 -or $b[$i - 1] -ne 13) { $bad++ } } }
    Check "$($f.Name): CRLF" ($lf -gt 0 -and $bad -eq 0) "($bad Zeilen nur mit LF)"
    if ($f.Extension -eq '.ps1') {
        $tok = $null; $err = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
        Check "$($f.Name): Syntax" ($err.Count -eq 0) (($err | Select-Object -First 3 | ForEach-Object { "Zeile $($_.Extent.StartLineNumber): $($_.Message)" }) -join '; ')
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
        $bad = @(if ($ast.ParamBlock) { $ast.ParamBlock.Parameters | Where-Object { $_.DefaultValue -and $_.DefaultValue.Extent.Text -match 'PSScriptRoot|PSCommandPath' } })
        Check "$($f.Name): keine Standardwerte mit `$PSScriptRoot (in 5.1 dort leer)" ($bad.Count -eq 0) (($bad | ForEach-Object { $_.Name.Extent.Text }) -join ', ')
    }
}

# ------------------------------------------------------------------ Testdaten
$pca2011 = New-TestCert 'CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, C=US'
$win2023 = New-TestCert 'CN=Windows UEFI CA 2023, O=Microsoft Corporation, C=US'
$kek2023 = New-TestCert 'CN=Microsoft Corporation KEK 2K CA 2023, O=Microsoft Corporation, C=US'
$haveCerts = [bool]($pca2011 -and $win2023 -and $kek2023)
if (-not $haveCerts) { Write-Host "  [??]   Testzertifikate nicht erzeugbar (.NET zu alt) - Zertifikatstests entfallen" -ForegroundColor Yellow }

$hashEsl  = New-HashEsl 5
$garbage  = Cat-Bytes @($hashEsl, [byte[]](1..40))
$certEsl  = if ($haveCerts) { New-Esl $X509Guid @(,$win2023.RawData) } else { $null }
$otherEsl = New-Esl ([Guid]::NewGuid()) @(,(New-Object byte[] 20))

New-AuthFile (Join-Path $tmp 'dbxupdate.bin')            (Cat-Bytes @($hashEsl, (New-HashEsl 3)))
New-AuthFile (Join-Path $tmp 'dbxupdate_wrapped.bin')    $hashEsl -Wrapped
New-AuthFile (Join-Path $tmp 'dbx_garbage.bin')          $garbage
New-AuthFile (Join-Path $tmp 'DBXUpdate2024.bin')        $hashEsl
New-AuthFile (Join-Path $tmp 'unknown_type.bin')         $otherEsl
if ($haveCerts) {
    New-AuthFile (Join-Path $tmp 'DBXUpdateSVN_pca.bin') (New-Esl $X509Guid @(,$pca2011.RawData))
    New-AuthFile (Join-Path $tmp 'DBUpdate2023.bin')     $certEsl
    New-AuthFile (Join-Path $tmp 'KEKUpdate_2023.bin')   (New-Esl $X509Guid @(,$kek2023.RawData))
}

# ------------------------------------------------------------------ 1b. Aufbau
Head "Aufbau: Starter, gemeinsame Funktionen, alte Namen"
$common = Join-Path $root 'SecureBootCommon.ps1'
Check "SecureBootCommon.ps1 vorhanden" (Test-Path $common)
foreach ($f in @(Get-ChildItem $root -Filter *.cmd -File)) {
    $txt = [IO.File]::ReadAllText($f.FullName)
    $ps = if ($txt -match '%~dp0([^"\s]+\.ps1)') { $Matches[1] } else { '' }
    Check "$($f.Name): startet ein vorhandenes Skript ($ps)" ($ps -and (Test-Path (Join-Path $root $ps)))
}
foreach ($f in @(Get-ChildItem $root -Filter *.ps1 -File | Where-Object { $_.Name -ne 'SecureBootCommon.ps1' })) {
    Check "$($f.Name): laedt SecureBootCommon.ps1" ([IO.File]::ReadAllText($f.FullName) -match "SecureBootCommon\.ps1")
}
foreach ($f in @(Get-ChildItem $root -Filter *.ps1 -File) + @(Get-Item $PSCommandPath)) {
    $tok = $null; $err = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
    $clash = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name } | Where-Object { Get-Alias -Name $_ -ErrorAction SilentlyContinue } | Select-Object -Unique)
    Check "$($f.Name): keine Funktion heisst wie ein Alias" ($clash.Count -eq 0) (($clash -join ', ') + ' (Alias gewinnt, Funktion wird nie aufgerufen)')
}
$old = '3_Manuell|4_Manuell|5_Manuell|6_Schluessel|7_Sicherung|8_dbx|IncludeDbx|DbxStepwise|dbx_schrittweise'
foreach ($f in @(Get-ChildItem $root -File | Where-Object { $_.Extension -in '.ps1', '.cmd', '.md', '.txt' })) {
    $hits = @(Select-String -Path $f.FullName -Pattern $old -AllMatches | ForEach-Object { $_.LineNumber })
    Check "$($f.Name): keine alten Starternamen" ($hits.Count -eq 0) ("Zeilen " + ($hits -join ', '))
}

# ------------------------------------------------------------------ 2a. Gemeinsame Funktionen
Head "SecureBootCommon.ps1: Parser und Entscheidungen"
. $common

$e = Parse-Esl $hashEsl
Check "Hashliste: 5 Hashes, gueltig" ($e.Hashes -eq 5 -and $e.Unique -eq 5 -and $e.Valid)
Check "Leere Variable gilt als gueltig" ((Parse-Esl ([byte[]]@())).Valid)
$e = Parse-Esl $garbage
Check "Hashliste mit Muell dahinter: ungueltig, sauberer Teil benannt" (-not $e.Valid -and $e.GoodBytes -eq $hashEsl.Length)
Check "Doppelte Hashes erkannt" ((Parse-Esl (Cat-Bytes @($hashEsl, $hashEsl))).Unique -eq 5)
Check "Get-CleanDbx entfernt den Muell" ((Get-CleanDbx $garbage).Length -eq $hashEsl.Length)
Check "Get-CleanDbx entfernt unbekannte Listen" ((Get-CleanDbx (Cat-Bytes @($hashEsl, $otherEsl))).Length -eq $hashEsl.Length)
Check "Unbekannter Typ wird als Other gezaehlt" ((Parse-Esl $otherEsl).Other -eq 1)
Check "Unwrap: normales Format bleibt unveraendert" (-not (Unwrap-Content $hashEsl).Wrapped)
$dd = Get-DedupDbx (Cat-Bytes @($hashEsl, $hashEsl, (New-HashEsl 2)))
Check "Get-DedupDbx: doppelte Hashes zusammengefasst" ((Parse-Esl $dd).Hashes -eq 7 -and (Parse-Esl $dd).Valid)
Check "Get-DedupDbx: leere Eingabe bleibt leer" ((Get-DedupDbx ([byte[]]@())).Length -eq 0)
$h1 = New-HashEsl 3; $h2 = New-HashEsl 2
$have = Get-EslHashes $h1
Check "Get-EslHashes zaehlt Hashes" ($have.Count -eq 3)
$both = Get-EslHashes (Cat-Bytes @($h1, $h2))
Check "Get-EslHashes erkennt Neues" (@($both | Where-Object { -not $have.Contains($_) }).Count -eq 2)
Check "Get-EslHashes ignoriert Muell" ((Get-EslHashes $garbage).Count -eq 5)
if ($haveCerts) {
    $e = Parse-Esl (Cat-Bytes @($certEsl, $hashEsl))
    Check "Zertifikat + Hashes erkannt" ($e.Certs.Count -eq 1 -and $e.Hashes -eq 5 -and $e.Valid)
    Check "Get-CleanDbx entfernt Zertifikate" ((Get-CleanDbx (Cat-Bytes @($certEsl, $hashEsl))).Length -eq $hashEsl.Length)
}

function P([string]$n) { Read-AuthPayload (Join-Path $tmp $n) }
function Renamed($p, [string]$Name) { $c = $p.PSObject.Copy(); $c.Name = $Name; $c }
$p = P 'dbxupdate.bin'
Check "Auth-Datei gelesen, 8 Hashes" ($p -and $p.Hashes -eq 8 -and $p.Valid -and -not $p.Wrapped)
Check "Ziel dbx" ((Get-PayloadTarget $p) -eq 'dbx')
Check "dbx-Datei: erlaubt" ($null -eq (Get-SkipReason $p 'dbx' 0))
Check "Dummy-Signatur: KEK unbekannt" ($p.SignedBy -eq '?')
$k23 = $p.PSObject.Copy(); $k23.SignedBy = '2023'
Check "Mit KEK 2023 signiert, KEK 2023 fehlt: abgelehnt" ((Get-SkipReason $k23 'dbx' 0 $false) -match 'KEK 2023')
Check "Mit KEK 2023 signiert, KEK 2023 da: erlaubt" ($null -eq (Get-SkipReason $k23 'dbx' 0 $true))
$k11 = $p.PSObject.Copy(); $k11.SignedBy = '2011'
Check "Mit KEK 2011 signiert, KEK 2023 fehlt: erlaubt" ($null -eq (Get-SkipReason $k11 'dbx' 0 $false))
Check "SVN-Datei: abgelehnt" ([bool](Get-SkipReason (Renamed $p 'DBXUpdateSVN.bin') 'dbx' 0))
Check "x64-Datei: erlaubt" ($null -eq (Get-SkipReason (Renamed $p 'dbx_x64_Legacy.efiauth2') 'dbx' 0))
Check "ia32-Datei: abgelehnt" ([bool](Get-SkipReason (Renamed $p 'dbx_ia32_Legacy.efiauth2') 'dbx' 0))
Check "arm64-Datei: abgelehnt" ([bool](Get-SkipReason (Renamed $p 'dbx_arm64.efiauth2') 'dbx' 0))
$p = P 'dbxupdate_wrapped.bin'
Check "Aelteres Format: Kopf erkannt und abgeschnitten" ($p -and $p.Wrapped -and $p.Valid -and $p.Hashes -eq 5)
Check "Kaputte Datei: abgelehnt" ([bool](Get-SkipReason (P 'dbx_garbage.bin') 'dbx' 0))
$p = P 'DBXUpdate2024.bin'
Check "DBXUpdate2024: immer abgelehnt" ([bool](Get-SkipReason $p (Get-PayloadTarget $p) 0))
$p = P 'unknown_type.bin'
Check "Unbekannter Eintragstyp: abgelehnt" ([bool](Get-SkipReason $p (Get-PayloadTarget $p) 1))
Check "Neuaufbau: normale dbx erlaubt" ($null -eq (Get-DbxSkipReason (P 'dbxupdate.bin')))
Check "Neuaufbau: aelteres Format erlaubt" ($null -eq (Get-DbxSkipReason (P 'dbxupdate_wrapped.bin')))
Check "Neuaufbau: kaputte Datei abgelehnt" ([bool](Get-DbxSkipReason (P 'dbx_garbage.bin')))
Check "Neuaufbau: DBXUpdate2024 abgelehnt" ([bool](Get-DbxSkipReason (P 'DBXUpdate2024.bin')))
Check "Neuaufbau: unbekannter Typ abgelehnt" ([bool](Get-DbxSkipReason (P 'unknown_type.bin')))
if ($haveCerts) {
    $p = P 'DBXUpdateSVN_pca.bin'
    Check "dbx mit PCA-2011-Zertifikat: abgelehnt" ((Get-SkipReason $p (Get-PayloadTarget $p) 0) -match 'CA 2011')
    Check "Neuaufbau: PCA-2011-Sperre abgelehnt" ([bool](Get-DbxSkipReason $p))
    $p = P 'DBUpdate2023.bin'
    Check "db-Datei: Ziel db" ((Get-PayloadTarget $p) -eq 'db')
    Check "db-Datei fehlt noch: erlaubt" ($null -eq (Get-SkipReason $p 'db' 1))
    Check "db-Datei schon vorhanden: uebersprungen" ((Get-SkipReason $p 'db' 0) -eq 'bereits vorhanden')
    $p = P 'KEKUpdate_2023.bin'
    Check "KEK-Datei: Ziel KEK, fehlt noch: erlaubt" ((Get-PayloadTarget $p) -eq 'KEK' -and $null -eq (Get-SkipReason $p 'KEK' 1))
}

# ------------------------------------------------------------------ 2b. Check (1_)
Head "SecureBootCheck.ps1: Einlesen und Einordnung"
$script:MockVars = @{}
function Get-SecureBootUEFI { param([string]$Name, $ErrorAction) if (-not $script:MockVars.ContainsKey($Name)) { throw "nicht vorhanden" }; [pscustomobject]@{ Bytes = $script:MockVars[$Name] } }
foreach ($t in (Get-FunctionTexts (Join-Path $root 'SecureBootCheck.ps1') @('Get-EfiSignatureList', 'Get-ChainKind'))) { . ([scriptblock]::Create($t)) }
$script:MockVars['dbx'] = $hashEsl;  $l = Get-EfiSignatureList 'dbx'
Check "Variable sauber: Valid" ($l.Valid -and $l.Hashes -eq 5 -and $l.GoodBytes -eq $hashEsl.Length)
$script:MockVars['dbx'] = $garbage;  $l = Get-EfiSignatureList 'dbx'
Check "Variable beschaedigt: erkannt" (-not $l.Valid -and $l.GoodBytes -eq $hashEsl.Length)
Check "Fehlende Variable: null" ($null -eq (Get-EfiSignatureList 'KEK'))
if ($haveCerts) {
    Check "Einordnung Windows 2023" ((Get-ChainKind @($win2023)) -match '2023')
    Check "Einordnung Windows 2011" ((Get-ChainKind @($pca2011)) -match '2011')
}
Check "Einordnung ohne Signatur" ((Get-ChainKind @()) -match 'keine')
Remove-Item Function:\Get-SecureBootUEFI

# ------------------------------------------------------------------ 2c. Windows 11 (6_)
Head "Win11Check.ps1: Bewertungen"
foreach ($t in (Get-FunctionTexts (Join-Path $root 'Win11Check.ps1') @('New-Rating', 'Test-CpuOfficial', 'Get-CpuRating', 'Get-RamRating', 'Get-DiskRating', 'Get-WddmFromDriverVersion', 'Get-MaxFeatureLevel', 'Get-GpuRating', 'Get-TpmRating', 'Get-SbRating', 'Get-Summary'))) { . ([scriptblock]::Create($t)) }
function Lv($r) { $r.Level }
$cpus = @(
    @('Intel(R) Core(TM)2 Duo CPU     E8400  @ 3.00GHz', $false, 'Bad'),
    @('Intel(R) Core(TM) i5-3470 CPU @ 3.20GHz', $true, 'Warn'),
    @('Intel(R) Core(TM) i7 CPU         920  @ 2.67GHz', $true, 'Warn'),
    @('Intel(R) Core(TM) i5 CPU         750  @ 2.67GHz', $true, 'Warn'),
    @('Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz', $true, 'Warn'),
    @('Intel(R) Core(TM) i7-7820HQ CPU @ 2.90GHz', $true, 'Ok'),
    @('Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz', $true, 'Warn'),
    @('Intel(R) Core(TM) i5-8500 CPU @ 3.00GHz', $true, 'Ok'),
    @('Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz', $true, 'Ok'),
    @('11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz', $true, 'Ok'),
    @('Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz', $true, 'Ok'),
    @('12th Gen Intel(R) Core(TM) i5-1235U', $true, 'Ok'),
    @('Intel(R) Core(TM) Ultra 7 155H', $true, 'Ok'),
    @('Intel(R) Core(TM) 5 120U', $true, 'Ok'),
    @('Intel(R) N100', $true, 'Ok'),
    @('Intel(R) Core(TM) i3-N305', $true, 'Ok'),
    @('Intel(R) Pentium(R) Gold G5400 CPU @ 3.70GHz', $true, 'Ok'),
    @('Intel(R) Pentium(R) CPU G4560 @ 3.50GHz', $true, 'Warn'),
    @('Intel(R) Celeron(R) N4020 CPU @ 1.10GHz', $true, 'Ok'),
    @('Intel(R) Celeron(R) CPU N3350 @ 1.10GHz', $true, 'Warn'),
    @('Intel(R) Celeron(R) CPU G1840 @ 2.80GHz', $true, 'Warn'),
    @('Intel(R) Xeon(R) CPU E3-1245 v5 @ 3.50GHz', $true, 'Warn'),
    @('Intel(R) Xeon(R) E-2124 CPU @ 3.30GHz', $true, 'Ok'),
    @('Intel(R) Xeon(R) Silver 4210 CPU @ 2.20GHz', $true, 'Ok'),
    @('Intel(R) Xeon(R) Silver 4110 CPU @ 2.10GHz', $true, 'Warn'),
    @('AMD Phenom(tm) II X4 965 Processor', $false, 'Bad'),
    @('AMD FX(tm)-8350 Eight-Core Processor', $true, 'Warn'),
    @('AMD A10-7850K Radeon R7, 12 Compute Cores 4C+8G', $true, 'Warn'),
    @('AMD Ryzen 5 1600 Six-Core Processor', $true, 'Warn'),
    @('AMD Ryzen 5 2600 Six-Core Processor', $true, 'Ok'),
    @('AMD Ryzen 7 PRO 4750U with Radeon Graphics', $true, 'Ok'),
    @('AMD Ryzen Threadripper 1950X 16-Core Processor', $true, 'Warn'),
    @('AMD Ryzen AI 9 HX 370 w/ Radeon 890M', $true, 'Ok'),
    @('AMD Athlon Silver 3050U with Radeon Graphics', $true, 'Ok'),
    @('AMD Athlon 200GE with Radeon Vega Graphics', $true, 'Warn'),
    @('AMD EPYC 7302P 16-Core Processor', $true, 'Ok'),
    @('Exotic CPU 3000', $true, 'Warn')
)
foreach ($c in $cpus) {
    $r = Get-CpuRating $c[0] $c[1] $true
    Check ("CPU {0} -> {1}" -f ($c[0] -replace '\s+', ' '), $c[2]) ($r.Level -eq $c[2]) "(war $($r.Level): $($r.Text))"
}
Check "CPU 32 Bit -> Bad" ((Lv (Get-CpuRating 'Intel(R) Core(TM) i5-8500' $true $false)) -eq 'Bad')
Check "CPU 1 Kern -> Bad" ((Lv (Get-CpuRating 'Intel(R) Core(TM) i5-8500' $true $true 1 3000)) -eq 'Bad')
Check "RAM 2 GB -> Bad"   ((Lv (Get-RamRating 2)) -eq 'Bad')
Check "RAM 4 GB -> Warn"  ((Lv (Get-RamRating 4)) -eq 'Warn')
Check "RAM 8 GB -> Warn"  ((Lv (Get-RamRating 7.9)) -eq 'Warn')
Check "RAM 16 GB -> Ok"   ((Lv (Get-RamRating 16)) -eq 'Ok')
Check "Disk 32 GB SSD -> Bad"   ((Lv (Get-DiskRating 32 'SSD')) -eq 'Bad')
Check "Disk 500 GB HDD -> Warn" ((Lv (Get-DiskRating 500 'HDD')) -eq 'Warn')
Check "Disk 120 GB SSD -> Warn" ((Lv (Get-DiskRating 119 'SSD')) -eq 'Warn')
Check "Disk 256 GB ? -> Warn"   ((Lv (Get-DiskRating 256 '')) -eq 'Warn')
Check "Disk 256 GB SSD -> Ok"   ((Lv (Get-DiskRating 238 'SSD')) -eq 'Ok')
Check "Treiber 27.20.100.8681 -> WDDM 2.7" ((Get-WddmFromDriverVersion '27.20.100.8681') -eq 2.7)
Check "Treiber 31.0.101.4502 -> WDDM 3.1"  ((Get-WddmFromDriverVersion '31.0.101.4502') -eq 3.1)
Check "Treiber 10.18.10.4358 -> WDDM 1.x"  ((Get-WddmFromDriverVersion '10.18.10.4358') -eq 1.0)
Check "Feature Level aus Liste"            ((Get-MaxFeatureLevel '11_1,12_1,12_0,10_0') -eq 12.1)
Check "GPU WDDM 2.7, FL 12_1 -> Ok"  ((Lv (Get-GpuRating 'Intel UHD 630' 2.7 12.1)) -eq 'Ok')
Check "GPU Text mit Unterstrich"     ((Get-GpuRating 'Intel UHD 630' 2.7 12.1).Text -match '12_1')
Check "GPU WDDM 1.3 -> Bad"          ((Lv (Get-GpuRating 'Intel HD 4000' 1.3 11.0)) -eq 'Bad')
Check "GPU FL 10_1 -> Bad"           ((Lv (Get-GpuRating 'alt' 2.0 10.1)) -eq 'Bad')
Check "GPU Basic Display -> Warn"    ((Lv (Get-GpuRating 'Microsoft Basic Display Adapter' 1.3 $null)) -eq 'Warn')
Check "GPU unbekannt -> Warn"        ((Lv (Get-GpuRating 'X' $null $null)) -eq 'Warn')
Check "TPM 2.0 -> Ok"                ((Lv (Get-TpmRating '2.0' $true)) -eq 'Ok')
Check "TPM 2.0 aus -> Warn"          ((Lv (Get-TpmRating '2.0' $false)) -eq 'Warn')
Check "TPM 1.2 -> Warn"              ((Lv (Get-TpmRating '1.2' $true)) -eq 'Warn')
Check "kein TPM -> Bad"              ((Lv (Get-TpmRating '' $null)) -eq 'Bad')
Check "Secure Boot Legacy -> Bad"    ((Lv (Get-SbRating $false $null $false $false)) -eq 'Bad')
Check "Secure Boot aus -> Bad"       ((Lv (Get-SbRating $true $false $true $true)) -eq 'Bad')
Check "Secure Boot 2011 -> Warn"     ((Lv (Get-SbRating $true $true $false $true)) -eq 'Warn')
Check "Secure Boot 2023 -> Ok"       ((Lv (Get-SbRating $true $true $true $true)) -eq 'Ok')
$okR = [ordered]@{ CPU = (New-Rating 'Ok' 'x'); RAM = (New-Rating 'Ok' 'x') }
Check "Zusammenfassung alles gruen -> Ok" ((Lv (Get-Summary $okR)) -eq 'Ok')
$okR['RAM'] = New-Rating 'Warn' 'x'
Check "Zusammenfassung gelb -> Warn"      ((Lv (Get-Summary $okR)) -eq 'Warn')
Check "Nur RAM knapp: offiziell moeglich"  ((Get-Summary $okR).Text -match '^Windows 11 ist offiziell moeglich\. Knapp.*RAM')
$okR['TPM'] = Get-TpmRating '1.2' $true
Check "TPM 1.2: nicht offiziell, RAM knapp" ((Get-Summary $okR).Text -match 'nicht offiziell unterstuetzt: TPM\. Knapp.*RAM')
$okR['TPM'] = Get-TpmRating '2.0' $false
Check "TPM aus: nur zu erledigen"         ((Get-Summary $okR).Text -match '^Windows 11 ist offiziell moeglich\. Knapp.*RAM, TPM')
$okR['TPM'] = Get-TpmRating '2.0' $true
$okR['CPU'] = Get-CpuRating 'Intel(R) Core(TM) i5-3470' $true $true
Check "Alte CPU: nicht offiziell"         ((Get-Summary $okR).Text -match 'nicht offiziell unterstuetzt: CPU')
$okR['CPU'] = Get-CpuRating 'Intel Core2 Duo E8400' $false $true
Check "Zusammenfassung alte CPU -> Bad"   ((Get-Summary $okR).Text -match 'Prozessor')

# ------------------------------------------------------------------ 3. Echte Dateien
$fx = Join-Path $testDir 'fixtures'
$sets = @(if (Test-Path $fx) { Get-ChildItem $fx -Directory })
Head ("Echte Dateien aus tests\fixtures ({0} Geraete)" -f $sets.Count)
if ($sets.Count -eq 0) { Write-Host "         keine vorhanden, auf einem Windows-PC Testdateien_sammeln.cmd ausfuehren" }
$k2011 = Join-Path $root 'dbx_KEK2011'
$extra = @(if (Test-Path $k2011) { Get-ChildItem $k2011 -Recurse -File | Where-Object { $_.Extension -in '.bin', '.efiauth2', '.auth2' } })
foreach ($f in $extra) {
    $p = Read-AuthPayload $f.FullName
    Check "dbx_KEK2011\$($f.Name): KEK-2011-signierte dbx, erlaubt ohne KEK 2023" ($p -and $p.SignedBy -eq '2011' -and (Get-PayloadTarget $p) -eq 'dbx' -and $null -eq (Get-SkipReason $p 'dbx' 0 $false))
}
foreach ($s in $sets) {
    foreach ($f in @(Get-ChildItem (Join-Path $s.FullName 'SecureBootUpdates') -Filter *.bin -ErrorAction SilentlyContinue)) {
        $p = Read-AuthPayload $f.FullName
        if (-not $p) { Write-Host ("         {0,-34} kein signiertes Variablen-Update (z.B. Sammeldatei), nicht geprueft" -f $f.Name); continue }
        $target = Get-PayloadTarget $p
        $skip = Get-SkipReason $p $target 1 $true
        Write-Host ("         {0,-34} Ziel {1,-3}  KEK {2,-4} {3} Zert. {4,5} Hashes  {5}{6}" -f $f.Name, $target, $p.SignedBy, $p.Certs.Count, $p.Hashes, $(if ($p.Wrapped) { 'altes Format  ' } else { '' }), $(if ($skip) { "-> nein: $skip" } else { '-> erlaubt' }))
        Check "$($s.Name)\$($f.Name): signierender KEK erkannt" ($p.SignedBy -ne '?')
        Check "$($s.Name)\$($f.Name): Inhalt erkannt" ($target -ne '?' -or $f.Name -notmatch 'db|kek')
        if (-not $p.Valid -or $p.Other -gt 0) { Check "$($s.Name)\$($f.Name): unsauber, daher abgelehnt" ([bool]$skip) }
        if ($f.Name -match 'DBXUpdate2024') {
            Check "$($s.Name)\$($f.Name): nie eingespielt" ([bool]$skip)
            Check "$($s.Name)\$($f.Name): Neuaufbau lehnt ab" ([bool](Get-DbxSkipReason $p))
        }
        if ($target -eq 'dbx' -and ($p.Certs | Where-Object { $_.Subject -match 'Production PCA 2011' })) { Check "$($s.Name)\$($f.Name): PCA-2011-Sperre abgelehnt" ([bool]$skip) }
    }
    foreach ($f in @(Get-ChildItem (Join-Path $s.FullName 'Variablen') -Filter *.bin -ErrorAction SilentlyContinue)) {
        $e = Parse-Esl ([IO.File]::ReadAllBytes($f.FullName))
        Write-Host ("         {0,-34} {1} Zert. {2,5} Hashes ({3} verschiedene)  {4}" -f $f.Name, $e.Certs.Count, $e.Hashes, $e.Unique, $(if ($e.Valid) { 'sauber' } else { 'BESCHAEDIGT' }))
        Check "$($s.Name)\Variablen\$($f.Name): sauber" $e.Valid
    }
}

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
$col = if ($script:fail) { 'Red' } else { 'Green' }
Write-Host ("Ergebnis: {0} bestanden, {1} fehlgeschlagen" -f $script:pass, $script:fail) -ForegroundColor $col
if (-not $NoPause) { Write-Host ""; Read-Host "Enter zum Beenden" | Out-Null }
exit $script:fail
