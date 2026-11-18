<#
.SYNOPSIS
    Secure-Boot-Schluessel ueber den Setup Mode neu aufbauen (4_Experte_Schluessel_neu_aufbauen.cmd)
    oder eine Sicherung zurueckspielen (5_Sicherung_zurueckspielen.cmd, -Restore).

.DESCRIPTION
    Im Setup Mode prueft die Firmware beim Schreiben keine Signaturen. So lassen sich KEK 2023 und
    dbx eintragen, ohne dass der Hersteller eine signierte Datei liefert. Der Original-PK wird zum
    Schluss wieder geschrieben. Das Skript erkennt selbst, welche Phase dran ist:

    Phase 1 (User Mode):  sichern, neue Inhalte bauen (alles Alte bleibt, es wird nur ergaenzt),
                          speichern unter Rebuild\<PC>\. Danach im Firmware-Setup die Schluessel
                          loeschen, Windows starten, Skript erneut ausfuehren.
    Phase 2 (Setup Mode): db, dbx, KEK und zuletzt PK schreiben. PK nur, wenn db und KEK geklappt haben.

    Nicht jede Firmware macht das mit (siehe README, z.B. HP Compaq Pro 6300).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\SecureBootRebuild.ps1
    powershell -ExecutionPolicy Bypass -File .\SecureBootRebuild.ps1 -Restore
#>
[CmdletBinding()]
param(
    [string]$PayloadDir = "$env:SystemRoot\System32\SecureBootUpdates",
    [string]$StateDir,          # anderer Ort fuer die Rebuild-Daten (z.B. Kopie auf dem Stick)
    [switch]$Restore,           # eine Sicherung aus Backups\<PC>\ zurueckschreiben
    [switch]$NoPause
)
$scriptDir = Split-Path -Parent $PSCommandPath
. (Join-Path $scriptDir 'SecureBootCommon.ps1')
Assert-Admin $PSCommandPath $PSBoundParameters
Initialize-Tool $(if ($Restore) { 'SecureBootRestore' } else { 'SecureBootRebuild' })
if (-not $StateDir) {
    $StateDir = Get-SubDir $localDir 'Rebuild'
    # Daten aus Version <= 1.2 liegen noch unter dem reinen Hostnamen
    $legacy = Join-Path (Join-Path $localDir 'Rebuild') $env:COMPUTERNAME
    if ($legacy -ne $StateDir -and -not (Test-Path (Join-Path $StateDir 'PK.esl')) -and (Test-Path (Join-Path $legacy 'PK.esl'))) { $StateDir = $legacy }
}
# Alter Zeitstempel wie in Microsofts Dateien: spaetere signierte Updates lassen sich so auch auf
# Firmwares anhaengen, die den Zeitstempel (faelschlich) pruefen.
$WriteTime = '2010-03-06T19:17:21Z'

function New-CertEsl([byte[]]$der) {
    $ms = New-Object IO.MemoryStream; $w = New-Object IO.BinaryWriter $ms
    $w.Write($X509Guid.ToByteArray()); $w.Write([UInt32](28 + 16 + $der.Length)); $w.Write([UInt32]0); $w.Write([UInt32](16 + $der.Length))
    $w.Write($MsOwnerGuid.ToByteArray()); $w.Write($der); $w.Flush()
    $ms.ToArray()
}

function Find-CertInBlob([byte[]]$b, [string]$pattern) {
    # Sucht DER-Zertifikate (30 82 xx xx 30 82 ...) in einer beliebigen Datei
    for ($i = 0; $i -lt $b.Length - 8; $i++) {
        if ($b[$i] -ne 0x30 -or $b[$i+1] -ne 0x82 -or $b[$i+4] -ne 0x30 -or $b[$i+5] -ne 0x82) { continue }
        $len = ($b[$i+2] * 256 + $b[$i+3]) + 4
        if ($len -lt 300 -or $i + $len -gt $b.Length) { continue }
        try {
            $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,[byte[]]$b[$i..($i + $len - 1)])
            if ($c.Subject -match $pattern) { return $c }
        } catch {}
    }
    $null
}
function Names($e) { ($e.Certs | ForEach-Object { Get-CN $_.Subject }) -join ', ' }

# ================================================================ Status
Section "Status"
$sys = Show-SystemInfo
$model = $sys.Model; $bios = $sys.Bios
try { $null = Confirm-SecureBootUEFI -ErrorAction Stop } catch { Bad "Kein UEFI, Abbruch."; Finish }
$setupMode = $null
try { $setupMode = (Get-SecureBootUEFI -Name SetupMode).Bytes[0] } catch {}
if ($Restore)             { Info ("Sicherung zurueckspielen, Firmware im {0}" -f $(if ($setupMode -eq 1) { 'Setup Mode' } else { 'User Mode' })) }
elseif ($setupMode -eq 1) { Warn "Setup Mode: Phase 2 (Zurueckschreiben)" }
else                      { Info "User Mode: Phase 1 (Vorbereiten)" }

# ================================================================ Sicherung zurueckspielen (5_)
if ($Restore) {
    Section "Sicherung zurueckspielen"
    # Backups\<PC>\Backup_* (von 3_) und Rebuild\<PC>\Original (von 4_), lokal und im Skriptordner
    $cands = @(); $seen = @{}
    foreach ($base in @($localDir, $scriptDir) | Select-Object -Unique) {
        foreach ($id in @($deviceId, $env:COMPUTERNAME) | Select-Object -Unique) {
            foreach ($kind in 'Backups', 'Rebuild') {
                $r = Join-Path (Join-Path $base $kind) $id
                if (-not (Test-Path $r)) { continue }
                foreach ($d in @(Get-ChildItem $r -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Backup_*' -or $_.Name -eq 'Original' })) {
                    $key = "$kind\$($d.Name)"
                    if ($seen.ContainsKey($key)) { continue }
                    $f = @{}
                    foreach ($n in 'PK', 'KEK', 'db', 'dbx') { foreach ($ext in 'esl', 'bin') { $x = Join-Path $d.FullName "$n.$ext"; if (-not $f[$n] -and (Test-Path $x)) { $f[$n] = $x } } }
                    if ($f['PK'] -and $f['KEK'] -and $f['db']) { $seen[$key] = $true; $cands += [pscustomobject]@{ Label = $key; Dir = $d.FullName; Time = $d.LastWriteTime; Files = $f } }
                }
            }
        }
    }
    $cands = @($cands | Sort-Object Time -Descending)
    if ($cands.Count -eq 0) { Bad "Keine Sicherung fuer dieses Geraet gefunden."; Finish }
    for ($i = 0; $i -lt $cands.Count; $i++) {
        $c = $cands[$i]
        $k = Parse-Esl ([IO.File]::ReadAllBytes($c.Files['KEK'])); $d = Parse-Esl ([IO.File]::ReadAllBytes($c.Files['db']))
        $x = if ($c.Files['dbx']) { Parse-Esl ([IO.File]::ReadAllBytes($c.Files['dbx'])) } else { $null }
        $kek23 = [bool]($k.Certs | Where-Object { $_.Subject -match 'KEK 2K CA 2023' })
        $win23 = [bool]($d.Certs | Where-Object { $_.Subject -match 'Windows UEFI CA 2023' })
        Info ("[{0}] {1}  ({2})  KEK 2023: {3}, Windows UEFI CA 2023: {4}, dbx: {5}{6}" -f ($i + 1), $c.Label, $c.Time.ToString('yyyy-MM-dd HH:mm'),
            $(if ($kek23) { 'ja' } else { 'nein' }), $(if ($win23) { 'ja' } else { 'nein' }), $(if ($x) { "$($x.Unique) Hashes" } else { 'keine' }),
            $(if (-not $k.Valid -or -not $d.Valid) { '  FEHLERHAFT' } elseif ($x -and -not $x.Valid) { '  (dbx wird bereinigt)' } else { '' }))
    }
    Write-Host ""
    if ($setupMode -ne 1) {
        Warn "Zum Zurueckschreiben muss die Firmware im Setup Mode sein:"
        Info ("  1. Neu starten, Schluessel loeschen: {0}" -f $vi.Clear)
        Info  "  2. Windows starten (falls noetig vorher Secure Boot aus), 5_Sicherung_zurueckspielen.cmd erneut."
        Finish
    }
    $sel = Read-Host "Nummer der Sicherung (leer = Abbruch)"
    $n = 0
    if (-not [int]::TryParse("$sel", [ref]$n) -or $n -lt 1 -or $n -gt $cands.Count) { Info "Abgebrochen, Firmware bleibt im Setup Mode."; Finish }
    $c = $cands[$n - 1]
    $k = Parse-Esl ([IO.File]::ReadAllBytes($c.Files['KEK'])); $d = Parse-Esl ([IO.File]::ReadAllBytes($c.Files['db']))
    if (-not $k.Valid -or -not $d.Valid) { Bad "KEK oder db dieser Sicherung sind fehlerhaft, Abbruch."; Finish }
    if (-not ($d.Certs | Where-Object { $_.Subject -match 'Windows UEFI CA 2023' })) {
        Warn "Ohne Windows UEFI CA 2023: Ist der Boot-Manager schon 2023-signiert, startet Windows mit Secure Boot nicht. Dann Secure Boot aus und 3_Zertifikate_einspielen.cmd."
    }
    $StateDir = Join-Path (Get-SubDir $localDir 'Restore') (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    foreach ($nm in 'PK', 'KEK', 'db', 'dbx') { if ($c.Files[$nm]) { Copy-Item $c.Files[$nm] (Join-Path $StateDir "$nm.esl") -Force } }
    "$env:COMPUTERNAME|$model|$($bios.SMBIOSBIOSVersion)|$($c.Time.ToString('s'))|$serial" | Set-Content (Join-Path $StateDir 'device.txt') -Encoding ASCII
    Info ("Gewaehlt: {0}" -f $c.Dir)
}

# ================================================================ Phase 1
if ($setupMode -ne 1) {
    Section "Phase 1: Vorbereiten"
    Info "Rebuild-Daten: $StateDir"
    $pk = Get-VarBytes 'PK'; $kek = Get-VarBytes 'KEK'; $db = Get-VarBytes 'db'; $dbx = Get-VarBytes 'dbx'
    if (-not $pk -or -not $kek -or -not $db) { Bad "PK, KEK oder db nicht lesbar, Abbruch."; Finish }
    # Hat die Firmware beim letzten "Schluessel loeschen" die Werksschluessel geladen statt den Setup Mode?
    $origDbFile = Join-Path $StateDir 'Original\db.esl'
    if (Test-Path $origDbFile) {
        $nowDb = Parse-Esl $db
        $lost = @((Parse-Esl ([IO.File]::ReadAllBytes($origDbFile))).Certs | Where-Object { $t = $_.Thumbprint; -not ($nowDb.Certs | Where-Object { $_.Thumbprint -eq $t }) })
        if ($lost.Count -gt 0) {
            Bad ("Seit dem letzten Lauf fehlen in der db: {0}" -f (($lost | ForEach-Object { Get-CN $_.Subject }) -join ', '))
            Bad "Die Firmware hat beim Loeschen die Werksschluessel geladen, der Setup-Mode-Weg geht hier so nicht."
            Info "Zurueck: Secure Boot aus (falls Windows nicht startet), 3_Zertifikate_einspielen.cmd, Secure Boot an."
            Finish
        }
    }
    $pkE = Parse-Esl $pk; $kekE = Parse-Esl $kek; $dbE = Parse-Esl $db
    Info ("PK:  {0}" -f (Names $pkE))
    if ($model -match 'Compaq Pro 6300') {
        Bad "Auf diesem Modell klappt der Neuaufbau nachweislich nicht: 'HP Keys' laedt nach dem Loeschen die Werksschluessel,"
        Bad "'Custom Keys' lehnt danach den HP-PK ab und Secure Boot laesst sich nicht mehr einschalten."
        if (-not (Confirm-JA "Trotzdem vorbereiten?")) { Info "Abgebrochen, nichts geaendert."; Finish }
    }
    if ($pkE.Certs | Where-Object { $_.Subject -match 'DO NOT TRUST|DO NOT SHIP' }) { Bad "PK ist ein Testschluessel (PKfail), der wuerde 1:1 zurueckgeschrieben. Abbruch."; Finish }
    if (-not (Test-Path $PayloadDir)) { Bad "Ordner $PayloadDir fehlt: erst alle Windows-Updates installieren."; Finish }

    # KEK
    $kekAdd = $null
    if ($kekE.Certs | Where-Object { $_.Subject -match 'KEK 2K CA 2023' }) { Ok "KEK 2023 ist schon vorhanden" }
    else {
        $msKek = $null
        $files = @(Get-Item (Join-Path $PayloadDir 'KEKUpdateCombined.bin') -ErrorAction SilentlyContinue) + @(Get-ChildItem $PayloadDir -File -ErrorAction SilentlyContinue)
        foreach ($f in $files) { if ($f) { $msKek = Find-CertInBlob ([IO.File]::ReadAllBytes($f.FullName)) 'KEK 2K CA 2023'; if ($msKek) { break } } }
        if ($msKek -and $msKek.Subject -match 'CN=Microsoft Corporation KEK 2K CA 2023') {
            Ok ("KEK + {0} (gueltig bis {1:yyyy-MM-dd})" -f (Get-CN $msKek.Subject), $msKek.NotAfter)
            $kekAdd = New-CertEsl $msKek.RawData
        } else { Warn "Microsoft KEK 2023 nicht gefunden, KEK bleibt wie er ist" }
    }
    $newKek = Join-Bytes @($kek, $kekAdd)

    # db
    $dbAdds = @()
    $have = @{}; foreach ($c in $dbE.Certs) { $have[$c.Thumbprint] = $true }
    $payloads = @(Get-ChildItem $PayloadDir -Filter *.bin -File -ErrorAction SilentlyContinue | ForEach-Object { Read-AuthPayload $_.FullName } | Where-Object { $_ })
    foreach ($p in $payloads | Where-Object { $_.Name -notmatch 'dbx|kek' -and $_.Valid -and $_.Other -eq 0 -and $_.Certs.Count -gt 0 }) {
        $missing = @($p.Certs | Where-Object { -not $have.ContainsKey($_.Thumbprint) })
        if ($missing.Count) {
            Ok ("db  + {0}" -f (($missing | ForEach-Object { Get-CN $_.Subject }) -join ', '))
            $dbAdds += ,$p.Content
            foreach ($c in $p.Certs) { $have[$c.Thumbprint] = $true }
        }
    }
    if ($dbAdds.Count -eq 0) { Ok "db hat bereits alle 2023-CAs" }
    $newDb = Join-Bytes (@(,$db) + $dbAdds)

    # dbx
    $dbxAdds = @()
    foreach ($p in $payloads | Where-Object { $_.Name -match 'dbx' }) {
        $why = Get-DbxSkipReason $p
        if ($why) { if ($why -ne 'keine Hashes') { Info ("dbx: {0} uebersprungen ({1})" -f $p.Name, $why) }; continue }
        $dbxAdds += ,$p.Content
    }
    $newDbx = Get-DedupDbx (Get-CleanDbx (Join-Bytes (@(,$dbx) + $dbxAdds)))
    $oldUnique = (Parse-Esl $dbx).Unique
    foreach ($chk in @(@('KEK', $newKek), @('db', $newDb), @('dbx', $newDbx))) {
        if (-not (Parse-Esl $chk[1]).Valid) { Bad ("Neuer {0}-Inhalt ist fehlerhaft, Abbruch." -f $chk[0]); Finish }
    }
    $nk = Parse-Esl $newKek; $nd = Parse-Esl $newDb; $nx = Parse-Esl $newDbx

    Section "Neuer Inhalt (wird in Phase 2 geschrieben)"
    Info "KEK: $(Names $nk)"
    Info "db:  $(Names $nd)"
    Info ("dbx: {0} Hashes, davon {1} neu" -f $nx.Hashes, ($nx.Hashes - $oldUnique))
    Info "PK:  unveraendert"
    if (-not ($nd.Certs | Where-Object { $_.Subject -match 'Windows UEFI CA 2023' })) { Warn "db haette keine Windows UEFI CA 2023" }
    if (-not $kekAdd -and $dbAdds.Count -eq 0 -and $nx.Hashes -le $oldUnique) { Ok "Nichts zu ergaenzen."; Finish }
    Write-Host ""
    if (-not (Confirm-JA "Rebuild-Daten speichern?")) { Info "Abgebrochen."; Finish }

    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    $bk = Join-Path $StateDir 'Original'; New-Item -ItemType Directory -Path $bk -Force | Out-Null
    foreach ($e in @(@('PK.esl', $pk), @('KEK.esl', $newKek), @('db.esl', $newDb), @('dbx.esl', $newDbx))) { [IO.File]::WriteAllBytes((Join-Path $StateDir $e[0]), $e[1]) }
    foreach ($e in @(@('PK.esl', $pk), @('KEK.esl', $kek), @('db.esl', $db), @('dbx.esl', $dbx))) { if ($e[1]) { [IO.File]::WriteAllBytes((Join-Path $bk $e[0]), $e[1]) } }
    "$env:COMPUTERNAME|$model|$($bios.SMBIOSBIOSVersion)|$(Get-Date -Format s)|$serial" | Set-Content (Join-Path $StateDir 'device.txt') -Encoding ASCII
    Ok "Gespeichert in $StateDir"
    if (-not $sameDir) {
        try { $dest = Get-SubDir $scriptDir 'Rebuild'; Copy-Item -Path (Join-Path $StateDir '*') -Destination $dest -Recurse -Force -ErrorAction Stop; Ok "Kopie im Skriptordner: $dest" } catch { Warn "Kopie in den Skriptordner fehlgeschlagen: $_" }
    }
    Suspend-BitLockerOnce

    Section "Naechste Schritte"
    Info ("1. Neu starten, im Firmware-Setup die Schluessel loeschen: {0}" -f $vi.Clear)
    Info  "2. Windows starten (im Setup Mode wird Secure Boot nicht erzwungen)."
    Info  "3. 4_Experte_Schluessel_neu_aufbauen.cmd erneut ausfuehren (Phase 2)."
    Warn  "Startet Windows nach dem Loeschen nicht: Secure Boot aus, dann weiter mit Schritt 3."
    Finish
}

# ================================================================ Phase 2
Section "Phase 2: Zurueckschreiben"
if (-not (Test-Path (Join-Path $StateDir 'PK.esl'))) {
    Bad "Keine Rebuild-Daten in $StateDir."
    Info "Kopie vom Stick angeben (-StateDir <Stick>\Rebuild\$deviceId) oder im Firmware-Setup die Werksschluessel laden."
    Finish
}
$dev = (Get-Content (Join-Path $StateDir 'device.txt') -ErrorAction SilentlyContinue) -split '\|'
$idMismatch = if ($dev.Count -ge 5 -and $dev[4] -and $serial) { $dev[4] -ne $serial } else { $dev[0] -ne $env:COMPUTERNAME }
if ($dev.Count -ge 2 -and ($idMismatch -or $dev[1] -ne $model)) { Bad ("Die Daten gehoeren zu '{0}' ({1}), nicht zu diesem Geraet. Abbruch." -f $dev[0], $dev[1]); Finish }
Info ("Daten vom {0}" -f $dev[3])
foreach ($f in 'PK.esl', 'KEK.esl', 'db.esl') {
    if (-not (Parse-Esl ([IO.File]::ReadAllBytes((Join-Path $StateDir $f)))).Valid) { Bad "$f ist fehlerhaft. Rebuild-Ordner loeschen und Phase 1 neu durchlaufen."; Finish }
}
$dbxPath = Join-Path $StateDir 'dbx.esl'
if (Test-Path $dbxPath) {
    $dbxRaw = [IO.File]::ReadAllBytes($dbxPath)
    # Neuaufbau: nur Hash-Sperren, jeder Hash einmal. Zurueckspielen: nur bereinigen, wenn beschaedigt.
    if (-not $Restore -or -not (Parse-Esl $dbxRaw).Valid) {
        $dbxOk = if ($Restore) { Get-CleanDbx $dbxRaw } else { Get-DedupDbx (Get-CleanDbx $dbxRaw) }
        if ($dbxOk.Length -ne $dbxRaw.Length) { Warn ("dbx bereinigt ({0} -> {1} Bytes)" -f $dbxRaw.Length, $dbxOk.Length); [IO.File]::WriteAllBytes($dbxPath, $dbxOk) }
    }
    if ((Get-Item $dbxPath).Length -eq 0) { Remove-Item $dbxPath -Force }
}
$steps = @(@{ Name = 'db'; File = 'db.esl'; Critical = $true })
if (Test-Path $dbxPath) { $steps += @{ Name = 'dbx'; File = 'dbx.esl'; Critical = $false } }
$steps += @{ Name = 'KEK'; File = 'KEK.esl'; Critical = $true }
foreach ($s in $steps) {
    $e = Parse-Esl ([IO.File]::ReadAllBytes((Join-Path $StateDir $s.File)))
    Info ("{0,-4} {1}{2}" -f $s.Name, (Names $e), $(if ($e.Hashes) { " $($e.Unique) Hashes" } else { '' }))
}
Info "PK   Original des Herstellers, wird zuletzt geschrieben"
Write-Host ""
if (-not (Confirm-JA "Jetzt db, dbx, KEK und PK schreiben?")) { Info "Abgebrochen, Firmware bleibt im Setup Mode."; Finish }
Suspend-BitLockerOnce

function Write-Var([string]$Name, [string]$File) {
    $path = Join-Path $StateDir $File
    $want = [IO.File]::ReadAllBytes($path)
    try { Set-SecureBootUEFI -Name $Name -Time $WriteTime -ContentFilePath $path -ErrorAction Stop | Out-Null }
    catch { Bad ("{0}: abgelehnt ({1})" -f $Name, $_.Exception.Message); return $false }
    $got = Get-VarBytes $Name
    if (-not $got) { Bad "${Name}: danach nicht lesbar"; return $false }
    $gw = Parse-Esl $want; $gg = Parse-Esl $got
    $missing = @($gw.Certs | Where-Object { $t = $_.Thumbprint; -not ($gg.Certs | Where-Object { $_.Thumbprint -eq $t }) })
    if ($missing.Count -gt 0 -or ($gw.Hashes -gt 0 -and $gg.Hashes -eq 0)) { Bad ("{0}: geschrieben, aber unvollstaendig" -f $Name); return $false }
    Ok ("{0} geschrieben ({1} Zertifikate, {2} Hashes)" -f $Name, $gg.Certs.Count, $gg.Unique)
    $true
}

$critOk = $true
foreach ($s in $steps) {
    $r = Write-Var $s.Name $s.File
    if (-not $r -and $s.Critical) { $critOk = $false }
    if (-not $r -and -not $s.Critical) { Warn "$($s.Name) nicht kritisch, es geht weiter." }
}
if (-not $critOk) {
    Bad "db oder KEK fehlgeschlagen, der PK wird NICHT geschrieben. Die Firmware bleibt im Setup Mode."
    Info "Stehen KEK und db schon aus einem frueheren Lauf drin, lassen manche Firmwares sie nicht ueberschreiben:"
    Info "Schluessel im Firmware-Setup erneut loeschen und Phase 2 wiederholen."
    Info "Oder zurueck: Werksschluessel laden, Secure Boot aus, 3_Zertifikate_einspielen.cmd, Secure Boot an."
    Finish
}

$r = Write-Var 'PK' 'PK.esl'
$setupMode = $null; try { $setupMode = (Get-SecureBootUEFI -Name SetupMode).Bytes[0] } catch {}
if ($r -and $setupMode -eq 0) { Ok "PK geschrieben, Firmware ist wieder im User Mode" }
elseif ($r) { Ok "PK geschrieben. Manche Firmwares (z.B. Lenovo M93) wechseln erst nach dem Neustart in den User Mode." }
else {
    Warn "Die Firmware hat den Original-PK abgelehnt. Erneutes Ausfuehren hilft nicht."
    Info "Je nach Firmware:"
    Info " - setzt sie beim naechsten Start ihren Werks-PK selbst (z.B. HP ProDesk 400 G5, EliteBook 840 G3)."
    Info "   KEK und db bleiben, die dbx faellt zurueck: danach 3_Zertifikate_einspielen.cmd und 2_Update_anstossen.cmd."
    Info " - bleibt sie im Setup Mode und Secure Boot laesst sich nicht einschalten (z.B. HP Compaq Pro 6300, 'Custom Keys')."
    Info "   Zurueck: Secure Boot aus, Werksschluessel laden (HP: 'HP Keys'), Windows starten, 3_Zertifikate_einspielen.cmd, Secure Boot an."
    Info "NEU STARTEN und 1_Pruefen.cmd zeigt, welcher Fall vorliegt."
    Finish
}
Section "Fertig"
Info "1. NEU STARTEN, Secure Boot im Firmware-Setup ggf. wieder einschalten."
Info "2. 1_Pruefen.cmd: KEK 2023, db und dbx sollten gruen sein."
Info "3. 2_Update_anstossen.cmd, damit Windows den Stand uebernimmt."
Finish
