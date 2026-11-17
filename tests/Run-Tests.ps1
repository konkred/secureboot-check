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

# ------------------------------------------------------------------ 2a. Manual (3_/4_/5_)
Head "SecureBootManual.ps1: Parser und Entscheidungen"
foreach ($t in (Get-FunctionTexts (Join-Path $root 'SecureBootManual.ps1') @('Get-CN','Parse-Esl','Get-CleanDbx','Get-Cms','Get-Signers','Get-SignerKek','Unwrap-Content','Read-AuthPayload','Get-PayloadTarget','Get-SkipReason','Get-EslHashes','Get-StepSkipReason'))) { . ([scriptblock]::Create($t)) }

$e = Parse-Esl $hashEsl
Check "Hashliste: 5 Hashes, gueltig" ($e.Hashes -eq 5 -and $e.Valid)
Check "Leere Variable gilt als gueltig" ((Parse-Esl ([byte[]]@())).Valid)
$e = Parse-Esl $garbage
Check "Hashliste mit Muell dahinter: ungueltig" (-not $e.Valid)
Check "Get-CleanDbx entfernt den Muell" ((Get-CleanDbx $garbage).Length -eq $hashEsl.Length)
Check "Get-CleanDbx entfernt unbekannte Listen" ((Get-CleanDbx (Cat-Bytes @($hashEsl, $otherEsl))).Length -eq $hashEsl.Length)
Check "Unbekannter Typ wird als Other gezaehlt" ((Parse-Esl $otherEsl).Other -eq 1)
Check "Unwrap: normales Format bleibt unveraendert" (-not (Unwrap-Content $hashEsl).Wrapped)
if ($haveCerts) {
    $e = Parse-Esl (Cat-Bytes @($certEsl, $hashEsl))
    Check "Zertifikat + Hashes erkannt" ($e.Certs.Count -eq 1 -and $e.Hashes -eq 5 -and $e.Valid)
    Check "Get-CleanDbx entfernt Zertifikate" ((Get-CleanDbx (Cat-Bytes @($certEsl, $hashEsl))).Length -eq $hashEsl.Length)
}

function P([string]$n) { Read-AuthPayload (Join-Path $tmp $n) }
$p = P 'dbxupdate.bin'
Check "Auth-Datei gelesen, 8 Hashes" ($p -and $p.Hashes -eq 8 -and $p.Valid -and -not $p.Wrapped)
Check "Ziel dbx" ((Get-PayloadTarget $p) -eq 'dbx')
Check "dbx ohne -IncludeDbx: uebersprungen" ([bool](Get-SkipReason $p 'dbx' 0 $false))
Check "dbx mit -IncludeDbx: erlaubt" ($null -eq (Get-SkipReason $p 'dbx' 0 $true))
Check "Dummy-Signatur: KEK unbekannt" ($p.SignedBy -eq '?')
$k23 = $p.PSObject.Copy(); $k23.SignedBy = '2023'
Check "Mit KEK 2023 signiert, KEK 2023 fehlt: abgelehnt" ((Get-SkipReason $k23 'dbx' 0 $true $false) -match 'KEK 2023')
Check "Mit KEK 2023 signiert, KEK 2023 da: erlaubt" ($null -eq (Get-SkipReason $k23 'dbx' 0 $true $true))
Check "Schrittmodus: KEK-2023-Datei ohne KEK 2023 abgelehnt" ([bool](Get-StepSkipReason $k23 'dbxupdate.bin' $false))
$p = P 'dbxupdate_wrapped.bin'
Check "Aelteres Format: Kopf erkannt und abgeschnitten" ($p -and $p.Wrapped -and $p.Valid -and $p.Hashes -eq 5)
$p = P 'dbx_garbage.bin'
Check "Kaputte Datei: abgelehnt" ([bool](Get-SkipReason $p 'dbx' 0 $true))
$p = P 'DBXUpdate2024.bin'
Check "DBXUpdate2024: immer abgelehnt" ([bool](Get-SkipReason $p (Get-PayloadTarget $p) 0 $true))
$p = P 'unknown_type.bin'
Check "Unbekannter Eintragstyp: abgelehnt" ([bool](Get-SkipReason $p (Get-PayloadTarget $p) 1 $true))
if ($haveCerts) {
    $p = P 'DBXUpdateSVN_pca.bin'
    Check "dbx mit PCA-2011-Zertifikat: abgelehnt" ((Get-SkipReason $p (Get-PayloadTarget $p) 0 $true) -match 'PCA 2011|CA 2011')
    $p = P 'DBUpdate2023.bin'
    Check "db-Datei: Ziel db" ((Get-PayloadTarget $p) -eq 'db')
    Check "db-Datei fehlt noch: erlaubt" ($null -eq (Get-SkipReason $p 'db' 1 $false))
    Check "db-Datei schon vorhanden: uebersprungen" ((Get-SkipReason $p 'db' 0 $false) -eq 'bereits vorhanden')
    $p = P 'KEKUpdate_2023.bin'
    Check "KEK-Datei: Ziel KEK" ((Get-PayloadTarget $p) -eq 'KEK')
}

Head "SecureBootManual.ps1: dbx schrittweise (8_)"
$h1 = New-HashEsl 3; $h2 = New-HashEsl 2
Check "Get-EslHashes zaehlt Hashes" ((Get-EslHashes $h1).Count -eq 3)
$have = Get-EslHashes $h1
Check "Get-EslHashes erkennt Neues" (@(Get-EslHashes (Cat-Bytes @($h1, $h2)) | Where-Object { -not $have.Contains($_) }).Count -eq 2)
Check "Get-EslHashes ignoriert Muell" ((Get-EslHashes $garbage).Count -eq 5)
$p = P 'dbxupdate.bin'
Check "x64-Datei erlaubt" ($null -eq (Get-StepSkipReason $p 'dbx_x64_Legacy\dbx_x64_Legacy.efiauth2'))
Check "amd64-Ordner erlaubt" ($null -eq (Get-StepSkipReason $p 'amd64\DBXUpdate.bin'))
Check "x86-Datei abgelehnt" ([bool](Get-StepSkipReason $p 'x86\DBXUpdate.bin'))
Check "ia32-Datei abgelehnt" ([bool](Get-StepSkipReason $p 'dbx_ia32_Legacy.efiauth2'))
Check "arm64-Datei abgelehnt" ([bool](Get-StepSkipReason $p 'arm64\DBXUpdate.bin'))
$svn = P 'dbxupdate.bin'; $svn = $svn.PSObject.Copy(); $svn.Name = 'DBXUpdateSVN.bin'
Check "SVN-Datei abgelehnt" ([bool](Get-StepSkipReason $svn 'DBXUpdateSVN.bin'))
Check "DBXUpdate2024 abgelehnt" ([bool](Get-StepSkipReason (P 'DBXUpdate2024.bin') 'DBXUpdate2024.bin'))
Check "Kaputte Datei abgelehnt" ([bool](Get-StepSkipReason (P 'dbx_garbage.bin') 'dbx_garbage.bin'))

# ------------------------------------------------------------------ 2b. Rebuild (6_/7_)
Head "SecureBootRebuild.ps1: Parser und dbx-Entscheidung"
foreach ($t in (Get-FunctionTexts (Join-Path $root 'SecureBootRebuild.ps1') @('Get-CN','Parse-Esl','Get-CleanDbx','Unwrap-Content','Read-AuthPayload','Get-DbxSkipReason'))) { . ([scriptblock]::Create($t)) }
Check "Muell erkannt" (-not (Parse-Esl $garbage).Valid)
Check "Get-CleanDbx entfernt den Muell" ((Get-CleanDbx $garbage).Length -eq $hashEsl.Length)
Check "Normale dbx-Datei: erlaubt" ($null -eq (Get-DbxSkipReason (P 'dbxupdate.bin')))
Check "Aelteres Format: erlaubt" ($null -eq (Get-DbxSkipReason (P 'dbxupdate_wrapped.bin')))
Check "Kaputte Datei: abgelehnt" ([bool](Get-DbxSkipReason (P 'dbx_garbage.bin')))
Check "DBXUpdate2024: abgelehnt" ([bool](Get-DbxSkipReason (P 'DBXUpdate2024.bin')))
Check "Unbekannter Typ: abgelehnt" ([bool](Get-DbxSkipReason (P 'unknown_type.bin')))
if ($haveCerts) { Check "PCA-2011-Sperre: abgelehnt" ([bool](Get-DbxSkipReason (P 'DBXUpdateSVN_pca.bin'))) }

# ------------------------------------------------------------------ 2c. Check (1_)
Head "SecureBootCheck.ps1: Integritaetspruefung und Einordnung"
$script:MockVars = @{}
function Get-SecureBootUEFI { param([string]$Name, $ErrorAction) if (-not $script:MockVars.ContainsKey($Name)) { throw "nicht vorhanden" }; [pscustomobject]@{ Bytes = $script:MockVars[$Name] } }
foreach ($t in (Get-FunctionTexts (Join-Path $root 'SecureBootCheck.ps1') @('Get-CN','Get-EfiSignatureList','Get-ChainKind'))) { . ([scriptblock]::Create($t)) }
$script:MockVars['dbx'] = $hashEsl;  $l = Get-EfiSignatureList 'dbx'
Check "Variable sauber: Valid" ($l.Valid -and $l.Hashes -eq 5 -and $l.GoodBytes -eq $hashEsl.Length)
$script:MockVars['dbx'] = $garbage;  $l = Get-EfiSignatureList 'dbx'
Check "Variable beschaedigt: erkannt, sauberer Teil benannt" (-not $l.Valid -and $l.GoodBytes -eq $hashEsl.Length)
Check "Fehlende Variable: null" ($null -eq (Get-EfiSignatureList 'KEK'))
if ($haveCerts) {
    Check "Einordnung Windows 2023" ((Get-ChainKind @($win2023)) -match '2023')
    Check "Einordnung Windows 2011" ((Get-ChainKind @($pca2011)) -match '2011')
}
Check "Einordnung ohne Signatur" ((Get-ChainKind @()) -match 'keine')

# ------------------------------------------------------------------ 3. Echte Dateien
$fx = Join-Path $testDir 'fixtures'
$sets = @(if (Test-Path $fx) { Get-ChildItem $fx -Directory })
Head ("Echte Dateien aus tests\fixtures ({0} Geraete)" -f $sets.Count)
if ($sets.Count -eq 0) { Write-Host "         keine vorhanden - auf einem Windows-PC Testdateien_sammeln.cmd ausfuehren" }
foreach ($s in $sets) {
    # Manual-Funktionen fuer die Payloads
    foreach ($t in (Get-FunctionTexts (Join-Path $root 'SecureBootManual.ps1') @('Parse-Esl','Unwrap-Content','Get-Cms','Get-Signers','Get-SignerKek','Read-AuthPayload','Get-PayloadTarget','Get-SkipReason'))) { . ([scriptblock]::Create($t)) }
    foreach ($f in @(Get-ChildItem (Join-Path $s.FullName 'SecureBootUpdates') -Filter *.bin -ErrorAction SilentlyContinue)) {
        $p = Read-AuthPayload $f.FullName
        if (-not $p) { Write-Host ("         {0,-34} kein signiertes Variablen-Update (z.B. Sammeldatei), nicht geprueft" -f $f.Name); continue }
        $target = Get-PayloadTarget $p
        $skip = Get-SkipReason $p $target 1 $true
        Write-Host ("         {0,-34} Ziel {1,-3}  KEK {2,-4} {3} Zert. {4,5} Hashes  {5}{6}" -f $f.Name, $target, $p.SignedBy, $p.Certs.Count, $p.Hashes, $(if ($p.Wrapped) { 'altes Format  ' } else { '' }), $(if ($skip) { "-> nein: $skip" } else { '-> erlaubt' }))
        Check "$($s.Name)\$($f.Name): signierender KEK erkannt" ($p.SignedBy -ne '?')
        Check "$($s.Name)\$($f.Name): Inhalt erkannt" ($target -ne '?' -or $f.Name -notmatch 'db|kek')
        if (-not $p.Valid -or $p.Other -gt 0) { Check "$($s.Name)\$($f.Name): unsauber, daher abgelehnt" ([bool]$skip) }
        if ($f.Name -match 'DBXUpdate2024') { Check "$($s.Name)\$($f.Name): nie eingespielt" ([bool]$skip) }
        if ($target -eq 'dbx' -and ($p.Certs | Where-Object { $_.Subject -match 'Production PCA 2011' })) { Check "$($s.Name)\$($f.Name): PCA-2011-Sperre abgelehnt" ([bool]$skip) }
    }
    foreach ($t in (Get-FunctionTexts (Join-Path $root 'SecureBootRebuild.ps1') @('Parse-Esl','Unwrap-Content','Read-AuthPayload','Get-DbxSkipReason'))) { . ([scriptblock]::Create($t)) }
    foreach ($f in @(Get-ChildItem (Join-Path $s.FullName 'SecureBootUpdates') -Filter *.bin -ErrorAction SilentlyContinue)) {
        $p = Read-AuthPayload $f.FullName
        if ($p -and $f.Name -match 'DBXUpdate2024') { Check "$($s.Name)\$($f.Name): 6_ lehnt ab" ([bool](Get-DbxSkipReason $p)) }
    }
    foreach ($f in @(Get-ChildItem (Join-Path $s.FullName 'Variablen') -Filter *.bin -ErrorAction SilentlyContinue)) {
        $e = Parse-Esl ([IO.File]::ReadAllBytes($f.FullName))
        Write-Host ("         {0,-34} {1} Zert. {2,5} Hashes  {3}" -f $f.Name, $e.Certs.Count, $e.Hashes, $(if ($e.Valid) { 'sauber' } else { 'BESCHAEDIGT' }))
        Check "$($s.Name)\Variablen\$($f.Name): sauber" $e.Valid
    }
}

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
$col = if ($script:fail) { 'Red' } else { 'Green' }
Write-Host ("Ergebnis: {0} bestanden, {1} fehlgeschlagen" -f $script:pass, $script:fail) -ForegroundColor $col
if (-not $NoPause) { Write-Host ""; Read-Host "Enter zum Beenden" | Out-Null }
exit $script:fail
