<#
.SYNOPSIS
    Secure-Boot-Zertifikate 2023 und Sperrliste (dbx) von Hand einspielen (3_Zertifikate_einspielen.cmd).

.DESCRIPTION
    Fuer Geraete, bei denen das Windows-Update nicht greift (z.B. Microsoft-Sperre, Ereignis 1802).
    Nimmt nur von Microsoft signierte Dateien, haengt sie an (nichts wird geloescht) und laesst die
    Firmware die Signatur pruefen.

      1. Sicherung von PK, KEK, db, dbx (Backups\<PC>\)
      2. Plan: welche Datei wohin, was uebersprungen wird und warum
      3. Mit -Execute: einmal JA, dann der Reihe nach schreiben
         db (Windows UEFI CA 2023 zuerst), KEK (klappt nur mit Hersteller-Signatur), dbx

    dbx: Neuere Windows-Versionen liefern die Sperrliste nur noch mit dem KEK 2023 signiert. Fehlt der
    KEK 2023, nimmt das Skript die gleichwertigen KEK-2011-Fassungen von Microsoft aus dem Ordner
    dbx_KEK2011 neben dem Skript und bietet an, sie herunterzuladen.
    DBXUpdate2024*.bin (sperrt die alte Windows-CA 2011) wird NIE eingespielt.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\SecureBootManual.ps1              # nur Plan
    powershell -ExecutionPolicy Bypass -File .\SecureBootManual.ps1 -Execute     # schreiben
#>
[CmdletBinding()]
param(
    [switch]$Execute,
    [string]$PayloadDir = "$env:SystemRoot\System32\SecureBootUpdates",
    [string]$Kek2011Dir,        # Standard: dbx_KEK2011 neben dem Skript (unten gesetzt, $PSScriptRoot ist hier in 5.1 leer)
    [switch]$NoPause
)
$scriptDir = Split-Path -Parent $PSCommandPath
if (-not $Kek2011Dir) { $Kek2011Dir = Join-Path $scriptDir 'dbx_KEK2011' }
. (Join-Path $scriptDir 'SecureBootCommon.ps1')
Assert-Admin $PSCommandPath $PSBoundParameters
Initialize-Tool 'SecureBootManual'

# Gleichwertige dbx mit KEK-2011-Signatur (zusammen dieselben Hashes wie Windows' dbxupdate.bin)
$Kek2011Base  = 'https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/SignedByKEK2011/dbx_x64_Legacy'
$Kek2011Files = @(
    'dbx_x64_Legacy.efiauth2'
    'dbx_x64_2EA557C44B83C0AD6B71EFB7EDCC18B6337AD1C1D682155DD9451B051B62FF40.efiauth2'
    'dbx_x64_86A9482509A434CA61EA4D12B6010A9013E5D3FBFF09B14799EBC87C124BCFF0.efiauth2'
)

function Get-Esl([string]$Name) { Parse-Esl (Get-VarBytes $Name) }
function Short([string]$s, [int]$n) { if ($s.Length -gt $n) { '...' + $s.Substring($s.Length - $n + 3) } else { $s } }

function Get-Kek2011Files {
    # Laedt die drei Dateien von Microsoft (GitHub) und behaelt nur, was sauber als KEK-2011-signierte dbx erkannt wird
    New-Item -ItemType Directory -Path $Kek2011Dir -Force -ErrorAction SilentlyContinue | Out-Null
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
    $n = 0
    foreach ($f in $Kek2011Files) {
        $dest = Join-Path $Kek2011Dir $f
        try {
            Invoke-WebRequest -Uri "$Kek2011Base/$f" -OutFile $dest -UseBasicParsing -ErrorAction Stop
            $p = Read-AuthPayload $dest
            if ($p -and $p.Valid -and $p.SignedBy -eq '2011' -and $p.Certs.Count -eq 0 -and $p.Hashes -gt 0) { Ok ("{0} geladen ({1} Hashes)" -f $f, $p.Hashes); $n++ }
            else { Bad "$f ist keine KEK-2011-signierte Sperrliste, geloescht"; Remove-Item $dest -Force -ErrorAction SilentlyContinue }
        } catch { Bad "$f nicht ladbar: $($_.Exception.Message)" }
    }
    $n
}

function Get-DbxCandidates([System.Collections.Generic.HashSet[string]]$Have, [bool]$HasKek23) {
    # Alle dbx-Dateien aus Windows-Ordner und dbx_KEK2011, gleicher Inhalt nur einmal
    $out = @(); $seen = @{}
    $sha = [System.Security.Cryptography.SHA256]::Create()
    foreach ($src in @($PayloadDir, $Kek2011Dir)) {
        if (-not (Test-Path $src)) { continue }
        $files = if ($src -eq $Kek2011Dir) { Get-ChildItem $src -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.bin', '.efiauth2', '.auth2' } }
                 else { Get-ChildItem $src -Filter *.bin -File -ErrorAction SilentlyContinue }
        foreach ($f in @($files)) {
            $p = Read-AuthPayload $f.FullName
            if (-not $p -or (Get-PayloadTarget $p) -ne 'dbx') { continue }
            $key = [BitConverter]::ToString($sha.ComputeHash($p.Content))
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $hs = Get-EslHashes $p.Content
            $out += [pscustomobject]@{ P = $p; Hashes = $hs; New = @($hs | Where-Object { -not $Have.Contains($_) }).Count; Why = (Get-SkipReason $p 'dbx' 0 $HasKek23) }
        }
    }
    $out
}

# ================================================================ Vorpruefung
Section "Vorpruefung"
$sys = Show-SystemInfo
Info ("Notfall ({0}, Taste {1}): Secure Boot AUS. Schluessel-Reset nur, solange der Boot-Manager noch 2011-signiert ist." -f $vi.Vendor, $vi.Key)
try { $sbOn = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sbOn = $null }
if ($null -eq $sbOn) { Bad "Kein UEFI, Abbruch."; Finish }
if ($sbOn) { Ok "Secure Boot aktiv" } else { Warn "Secure Boot ist aus (Schreiben geht trotzdem)" }
$setup = $null; try { $setup = (Get-SecureBootUEFI -Name SetupMode).Bytes[0] } catch {}
if ($setup -eq 1) {
    Bad "Setup Mode: erst im Firmware-Setup die Werksschluessel laden (HP: Key Ownership 'HP Keys'). Abbruch."
    Finish
}
if (-not (Test-Path $PayloadDir)) { Warn "Ordner $PayloadDir fehlt: erst alle Windows-Updates installieren." }

# ================================================================ Sicherung
Section "Sicherung"
$script:backupDir = Join-Path (Get-SubDir $localDir 'Backups') ("Backup_{0}" -f (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'))
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
foreach ($n in 'PK', 'KEK', 'db', 'dbx') {
    $b = Get-VarBytes $n
    if ($b) { [IO.File]::WriteAllBytes((Join-Path $backupDir "$n.bin"), $b); Ok ("{0,-4} gesichert ({1} Bytes)" -f $n, $b.Length) } else { Warn "$n nicht lesbar" }
}

# ================================================================ Plan
$db = Get-Esl 'db'; $kek = Get-Esl 'KEK'
$have = @{}; foreach ($c in @($db.Certs) + @($kek.Certs)) { if ($c) { $have[$c.Thumbprint] = $true } }
$hasKek23 = [bool]($kek.Certs | Where-Object { $_.Subject -match 'KEK 2K CA 2023' })
$haveH = Get-EslHashes (Get-VarBytes 'dbx')

Section "Plan"
Info ("KEK 2023 eingetragen: {0}   dbx: {1} verschiedene Hashes" -f $(if ($hasKek23) { 'ja' } else { 'nein' }), $haveH.Count)
Write-Host ""

# db und KEK: gleiche Zertifikate aus mehreren Dateien = Ersatzdateien
$plan = @(); $planned = @{}
foreach ($f in @(Get-ChildItem -Path $PayloadDir -Filter *.bin -File -ErrorAction SilentlyContinue)) {
    $p = Read-AuthPayload $f.FullName
    if (-not $p) { continue }
    $target = Get-PayloadTarget $p
    if ($target -eq 'dbx') { continue }
    $what = if ($p.Certs.Count) { ($p.Certs | ForEach-Object { Get-CN $_.Subject }) -join ', ' } else { "$($p.Hashes) Hashes" }
    $missing = @($p.Certs | Where-Object { -not $have.ContainsKey($_.Thumbprint) }).Count
    $skip = Get-SkipReason $p $target $missing $hasKek23
    if ($skip) { Info ("--   {0,-28} {1}" -f $p.Name, $skip); continue }
    $certKey = (@($p.Certs | ForEach-Object { $_.Thumbprint }) | Sort-Object) -join ','
    if ($planned.ContainsKey($certKey)) { $planned[$certKey].Payloads += $p; continue }
    $order = if ($target -eq 'KEK') { 3 } elseif ($what -match 'Windows UEFI CA 2023') { 1 } else { 2 }
    $item = [pscustomobject]@{ Order = $order; Target = $target; What = $what; Payloads = @($p) }
    $plan += $item; $planned[$certKey] = $item
}
# Mit dem KEK 2011 signierte Ersatzdateien zuerst probieren
foreach ($s in $plan) { $s.Payloads = @($s.Payloads | Sort-Object { if ($_.SignedBy -eq '2011') { 0 } else { 1 } }) }
$plan = @($plan | Sort-Object Order)

# dbx
$dbxItems = @(Get-DbxCandidates $haveH $hasKek23)
$usable = @($dbxItems | Where-Object { -not $_.Why -and $_.New -gt 0 })
$blocked23 = @($dbxItems | Where-Object { $_.Why -match 'KEK 2023' -and $_.New -gt 0 })
$have2011 = @($dbxItems | Where-Object { $_.P.SignedBy -eq '2011' -and $_.P.File -like "$Kek2011Dir*" })
if ($usable.Count -eq 0 -and $blocked23.Count -gt 0 -and $have2011.Count -eq 0) {
    Warn ("Windows liefert die Sperrliste nur mit dem KEK 2023 signiert ({0} neue Hashes), der hier fehlt." -f ($blocked23 | Measure-Object New -Maximum).Maximum)
    Info "Microsoft stellt dieselben Hashes mit KEK-2011-Signatur bereit (github.com/microsoft/secureboot_objects)."
    if ($Execute -and (Confirm-JA "Die drei Dateien jetzt nach $Kek2011Dir herunterladen?")) {
        if ((Get-Kek2011Files) -gt 0) { $dbxItems = @(Get-DbxCandidates $haveH $hasKek23); $usable = @($dbxItems | Where-Object { -not $_.Why -and $_.New -gt 0 }) }
    } else { Info "Ohne Download: Dateien von Hand nach $Kek2011Dir legen." }
    Write-Host ""
}
foreach ($it in $dbxItems) {
    $why = if ($it.Why) { $it.Why } elseif ($it.New -eq 0) { 'alle Hashes schon enthalten' } else { $null }
    if ($why) { Info ("--   {0,-28} {1}" -f (Short $it.P.Name 28), $why) }
}
if ($usable.Count) { $plan += [pscustomobject]@{ Order = 4; Target = 'dbx'; What = ("bis zu {0} neue Hashes" -f ($usable | Measure-Object New -Maximum).Maximum); Payloads = @($usable | Sort-Object New -Descending | ForEach-Object { $_.P }) } }

if ($plan.Count -eq 0) { Write-Host ""; Ok "Nichts zu tun: alle passenden Zertifikate und Hashes sind schon eingetragen."; Finish }
Write-Host ""
foreach ($s in $plan) { Ok ("{0,-4} <- {1}   [{2}]" -f $s.Target, $s.What, (($s.Payloads | ForEach-Object { Short $_.Name 32 }) -join ' / ')) }
if ($plan | Where-Object { $_.Target -eq 'KEK' }) { Info "KEK: klappt nur, wenn die Datei mit dem PK dieses Geraets signiert ist. Eine Ablehnung ist harmlos." }

if (-not $Execute) { Write-Host ""; Warn "Nur Plan, nichts geschrieben. Zum Schreiben 3_Zertifikate_einspielen.cmd starten."; Finish }

# ================================================================ Schreiben
Write-Host ""
Warn ("Startet der PC danach nicht: Firmware-Setup ({0}, Taste {1}), Secure Boot AUS, dann 5_Sicherung_zurueckspielen.cmd." -f $vi.Vendor, $vi.Key)
if (-not (Confirm-JA "Plan jetzt ausfuehren?")) { Info "Abgebrochen."; Finish }
Suspend-BitLockerOnce
$tmp = Join-Path $env:TEMP ("sbmanual_{0}" -f (Get-Date -Format 'yyyyMMddHHmmss'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$okCount = 0
foreach ($s in $plan) {
    foreach ($pl in $s.Payloads) {
        if ($s.Target -eq 'dbx') {
            $hsP = Get-EslHashes $pl.Content
            $new = @($hsP | Where-Object { -not $haveH.Contains($_) }).Count
            if ($new -eq 0) { Info ("{0}: inzwischen alles enthalten" -f $pl.Name); continue }
        }
        $cFile = Join-Path $tmp 'content.bin'; $sFile = Join-Path $tmp 'sig.p7'
        [IO.File]::WriteAllBytes($cFile, $pl.Content); [IO.File]::WriteAllBytes($sFile, $pl.Sig)
        $before = (Get-VarBytes $s.Target).Length
        try {
            Set-SecureBootUEFI -Name $s.Target -Time $pl.Time -ContentFilePath $cFile -SignedFilePath $sFile -AppendWrite -ErrorAction Stop | Out-Null
            $after = (Get-VarBytes $s.Target).Length
            if ($s.Target -eq 'dbx') {
                $n0 = $haveH.Count; $haveH = Get-EslHashes (Get-VarBytes 'dbx')
                Ok ("dbx  {0}: angenommen, {1} -> {2} Hashes" -f $pl.Name, $n0, $haveH.Count); $okCount++
                continue
            }
            if ($after -gt $before) { Ok ("{0,-4} {1}: geschrieben ({2} -> {3} Bytes)" -f $s.Target, $pl.Name, $before, $after); $okCount++; break }
            Warn ("{0,-4} {1}: ohne Fehler, aber unveraendert" -f $s.Target, $pl.Name)
        } catch {
            Bad ("{0,-4} {1}: abgelehnt (0x{2:X8})" -f $s.Target, $pl.Name, $_.Exception.HResult)
        }
    }
}
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue

# ================================================================ Kontrolle
Section "Kontrolle"
$db = Get-Esl 'db'; $kek = Get-Esl 'KEK'; $dbxNow = Get-Esl 'dbx'
foreach ($n in 'Windows UEFI CA 2023', 'Microsoft UEFI CA 2023', 'Option ROM UEFI CA 2023') {
    if ($db.Certs | Where-Object { $_.Subject -match $n }) { Ok "db:  $n" } else { Bad "db:  $n fehlt" }
}
if ($kek.Certs | Where-Object { $_.Subject -match 'KEK 2K CA 2023' }) { Ok "KEK: Microsoft Corporation KEK 2K CA 2023" } else { Warn "KEK: KEK 2K CA 2023 fehlt (nur mit Hersteller-Datei oder 4_Experte_Schluessel_neu_aufbauen.cmd)" }
Info ("dbx: {0} verschiedene Hashes" -f $dbxNow.Unique)
if ($okCount -gt 0) {
    Write-Host ""
    Warn "Jetzt NEU STARTEN, dann 1_Pruefen.cmd."
    Info "Ist die Windows UEFI CA 2023 in der db, installiert 2_Update_anstossen.cmd den neuen Boot-Manager."
}
Finish
