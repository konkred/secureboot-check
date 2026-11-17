<#
.SYNOPSIS
    Secure-Boot-Schluessel ueber den SETUP MODE neu aufbauen:
    KEK + Microsoft KEK 2023, db + 2023-CAs, dbx + aktuelle Sperrliste, danach Original-PK.

.DESCRIPTION
    Fuer Geraete, bei denen Windows/Microsoft das Update sperrt (Ereignis 1802) oder die
    Firmware das Anhaengen ablehnt (0xC0000022). Im Setup Mode prueft die Firmware beim
    Schreiben keine Signaturen - so lassen sich KEK und dbx setzen, ohne dass der
    Hersteller eine signierte Datei liefern muss. Der Original-PK des Herstellers wird
    zum Schluss wieder eingetragen, die Firmware ist danach wieder im User Mode.

    ZWEI PHASEN (das Skript erkennt selbst, welche dran ist):

    PHASE 1 - Vorbereiten (Firmware im User Mode):
      - Sichert PK, KEK, db, dbx
      - Baut die neuen Inhalte (alte Eintraege bleiben ALLE erhalten, es wird nur ergaenzt):
          KEK  = alt + Microsoft Corporation KEK 2K CA 2023 (aus KEKUpdateCombined.bin)
          db   = alt + fehlende 2023-CAs
          dbx  = alt + dbxupdate.bin + DBXUpdateSVN.bin   (NIE die PCA-2011-Sperre)
          PK   = alt (unveraendert)
      - Speichert alles in C:\ProgramData\SecureBootCheck\Rebuild\<PC>\ (+ Kopie im Skriptordner)
      - Haelt BitLocker an
      -> Danach: Neustart ins Firmware-Setup, "Secure-Boot-Schluessel LOESCHEN"
         (Setup Mode), Windows starten, Skript erneut ausfuehren.

    PHASE 2 - Zurueckschreiben (Firmware im Setup Mode):
      - Schreibt db, dbx, KEK und zuletzt PK
      - PK wird nur geschrieben, wenn db und KEK erfolgreich waren
      - Prueft jeden Schritt durch Zuruecklesen

    NOTFALL: Bleibt die Firmware im Setup Mode, startet Windows trotzdem (Secure Boot wird
    dann nicht erzwungen). Skript erneut ausfuehren oder im Firmware-Setup Secure Boot aus
    und Schluessel auf Werkseinstellung, danach 4_Manuell_einspielen.cmd.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\SecureBootRebuild.ps1
#>
[CmdletBinding()]
param(
    [string]$PayloadDir = "$env:SystemRoot\System32\SecureBootUpdates",
    [string]$StateDir,          # anderer Ort fuer die Rebuild-Daten (z.B. Kopie auf dem Stick)
    [switch]$Restore,           # statt Neuaufbau: eine Sicherung aus Backups\<PC>\ zurueckschreiben (7_)
    [switch]$NoPause
)
$ScriptVersion = '1.3'

# ---------------------------------------------------------------- Admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-PayloadDir', "`"$PayloadDir`"")
    if ($StateDir) { $argList += @('-StateDir', "`"$StateDir`"") }
    if ($Restore)  { $argList += '-Restore' }
    if ($NoPause)  { $argList += '-NoPause' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

$scriptDir = Split-Path -Parent $PSCommandPath
$localDir  = Join-Path $env:ProgramData 'SecureBootCheck'
# Ordnerstruktur (lokal und im Skriptordner gleich):  Logs\<PC>\   Backups\<PC>\   Rebuild\<PC>\
# Geraete-ID fuer die Ordner: <Hostname>_<Seriennummer>, damit gleich benannte PCs (geklonte
# Images) nicht im selben Ordner landen. Ohne brauchbare Seriennummer: nur der Hostname.
function Get-Serial {
    $bad = '^(to be filled.*|default string|system serial number|none|n/?a|not (specified|available|applicable)|o\.?e\.?m\.?|0+|1234567890?|x+|chassis serial number)$'
    foreach ($q in @(@('Win32_BIOS','SerialNumber'), @('Win32_ComputerSystemProduct','IdentifyingNumber'), @('Win32_SystemEnclosure','SerialNumber'))) {
        try {
            $v = "$((Get-CimInstance $q[0] -ErrorAction Stop | Select-Object -First 1).($q[1]))".Trim()
            if ($v -match $bad) { continue }
            $v = ($v -replace '[^A-Za-z0-9-]', '')
            if ($v.Length -ge 4 -and $v -notmatch '^(.)\1+$' -and $v -notmatch '^(TOBEFILLED|DEFAULTSTRING|SYSTEMSERIAL)') { return $v.ToUpper() }
        } catch {}
    }
    ''
}
$serial   = Get-Serial
$deviceId = if ($serial) { "{0}_{1}" -f $env:COMPUTERNAME, $serial } else { $env:COMPUTERNAME }
function Get-SubDir([string]$Root, [string]$Kind) { $d = Join-Path (Join-Path $Root $Kind) $deviceId; New-Item -ItemType Directory -Path $d -Force -ErrorAction SilentlyContinue | Out-Null; $d }
$sameDir   = ($scriptDir.TrimEnd('\') -eq $localDir.TrimEnd('\'))
function Copy-ToScriptDir([string]$Path, [string]$Kind) {
    # Kopiert eine Datei/einen Ordner aus dem lokalen <Kind>\<PC>\ in den gleichen Unterordner im Skriptordner
    if ($sameDir -or -not (Test-Path $Path)) { return $null }
    try { $dest = Get-SubDir $scriptDir $Kind; Copy-Item -Path $Path -Destination $dest -Recurse -Force -ErrorAction Stop; $dest } catch { $null }
}
$logFile   = Join-Path (Get-SubDir $localDir 'Logs') ("SecureBootRebuild_{0}_{1}.txt" -f $deviceId, (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'))
try { Start-Transcript -Path $logFile -Force | Out-Null } catch {}
if (-not $StateDir) {
    $StateDir = Get-SubDir $localDir 'Rebuild'
    # Rebuild-Daten aus Version <= 1.2 liegen noch unter dem reinen Hostnamen
    $legacy = Join-Path (Join-Path $localDir 'Rebuild') $env:COMPUTERNAME
    if ($legacy -ne $StateDir -and -not (Test-Path (Join-Path $StateDir 'PK.esl')) -and (Test-Path (Join-Path $legacy 'PK.esl'))) { $StateDir = $legacy }
}

function Section([string]$t) { Write-Host ""; Write-Host ("=" * 70) -ForegroundColor DarkCyan; Write-Host " $t" -ForegroundColor Cyan; Write-Host ("=" * 70) -ForegroundColor DarkCyan }
function Ok([string]$t)   { Write-Host "  [OK]   $t" -ForegroundColor Green }
function Bad([string]$t)  { Write-Host "  [!!]   $t" -ForegroundColor Red }
function Warn([string]$t) { Write-Host "  [??]   $t" -ForegroundColor Yellow }
function Info([string]$t) { Write-Host "         $t" }
function Finish {
    try { Stop-Transcript | Out-Null } catch {}
    $d = Copy-ToScriptDir $logFile 'Logs'
    if ($d) { Write-Host "         Protokoll kopiert nach: $d" -ForegroundColor DarkGray }
    Write-Host "         Lokales Protokoll: $logFile" -ForegroundColor DarkGray
    if (-not $NoPause) { Write-Host ""; Read-Host "Enter zum Beenden" | Out-Null }
    exit
}
function Confirm-JA([string]$q) { (Read-Host "$q  Zum Bestaetigen JA tippen") -ceq 'JA' }

$X509Guid    = [Guid]'a5c059a1-94e4-4aa7-87b5-ab155c2bf072'
$Sha256Guid  = [Guid]'c1c41626-504c-4092-aca9-41f936934328'
$Pkcs7Guid   = [Guid]'4aafd29d-68df-49ee-8aa9-347d375665a7'
$MsOwnerGuid = [Guid]'77fa9abd-0359-4d32-bd60-28f4e78f784b'
# Zeitstempel wie in Microsofts Update-Dateien: alt, damit spaetere signierte Updates (2010er Zeitstempel)
# auch auf Firmwares angehaengt werden koennen, die den Zeitstempel (faelschlich) pruefen.
$WriteTime   = '2010-03-06T19:17:21Z'

function Get-CN([string]$dn) { if ($dn -match 'CN=([^,]+)') { $Matches[1].Trim() } else { $dn } }

function Parse-Esl([byte[]]$b) {
    $certs = @(); $hashes = 0; $other = 0; $o = 0
    if (-not $b) { return [pscustomobject]@{ Certs=@(); Hashes=0; Other=0; Valid=$true } }
    while ($o + 28 -le $b.Length) {
        $type     = New-Object Guid (,[byte[]]$b[$o..($o + 15)])
        $listSize = [BitConverter]::ToUInt32($b, $o + 16)
        $hdrSize  = [BitConverter]::ToUInt32($b, $o + 20)
        $sigSize  = [BitConverter]::ToUInt32($b, $o + 24)
        if ($listSize -lt 28 -or $sigSize -lt 16 -or ($o + $listSize) -gt $b.Length) { break }
        $p = $o + 28 + $hdrSize
        while ($p + $sigSize -le $o + $listSize) {
            if ($type -eq $X509Guid) {
                try { $certs += New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,[byte[]]$b[($p + 16)..($p + $sigSize - 1)]) } catch {}
            } elseif ($type -eq $Sha256Guid) { $hashes++ } else { $other++ }
            $p += $sigSize
        }
        $o += $listSize
    }
    # Valid = die Daten bestehen vollstaendig aus sauberen Signaturlisten (kein Rest, kein Muell)
    [pscustomobject]@{ Certs = $certs; Hashes = $hashes; Other = $other; Valid = ($o -eq $b.Length) }
}

function Get-CleanDbx([byte[]]$b) {
    # Behaelt nur saubere SHA256-Hashlisten - alles andere (Zertifikate, unbekannte Typen, Muell) faellt weg
    $l = New-Object System.Collections.Generic.List[byte]; $o = 0
    if (-not $b) { return ,([byte[]]@()) }
    while ($o + 28 -le $b.Length) {
        $type     = New-Object Guid (,[byte[]]$b[$o..($o + 15)])
        $listSize = [BitConverter]::ToUInt32($b, $o + 16)
        $sigSize  = [BitConverter]::ToUInt32($b, $o + 24)
        if ($listSize -lt 28 -or $sigSize -lt 16 -or ($o + $listSize) -gt $b.Length) { break }
        if ($type -eq $Sha256Guid) { $l.AddRange([byte[]]$b[$o..($o + $listSize - 1)]) }
        $o += $listSize
    }
    ,$l.ToArray()
}

function Unwrap-Content([byte[]]$c) {
    # Manche (aeltere) Microsoft-Dateien haben vor der Signaturliste noch
    # VariablenName(UTF-16) + VendorGuid + Attribute + EFI_TIME - das wird hier abgeschnitten.
    $known = @([Guid]'d719b2cb-3d3a-4596-a3bc-dad00e67656f', [Guid]'8be4df61-93ca-11d2-aa0d-00e098032b8c')
    for ($n = 2; $n -le 40 -and $n + 36 -le $c.Length; $n += 2) {
        $g = New-Object Guid (,[byte[]]$c[$n..($n + 15)])
        if ($known -contains $g) {
            $s = $n + 16 + 4 + 16
            if ($s -lt $c.Length) { return [pscustomobject]@{ Content = [byte[]]$c[$s..($c.Length - 1)]; Wrapped = $true } }
        }
    }
    [pscustomobject]@{ Content = $c; Wrapped = $false }
}

function Read-AuthPayload([string]$Path) {
    $b = [IO.File]::ReadAllBytes($Path)
    if ($b.Length -lt 48) { return $null }
    $year = [BitConverter]::ToUInt16($b, 0)
    $dwLength = [BitConverter]::ToUInt32($b, 16)
    if ($year -lt 2000 -or $year -gt 2100 -or [BitConverter]::ToUInt16($b, 22) -ne 0x0EF1) { return $null }
    if ((New-Object Guid (,[byte[]]$b[24..39])) -ne $Pkcs7Guid) { return $null }
    $cs = 16 + $dwLength
    if ($cs -ge $b.Length) { return $null }
    $content = (Unwrap-Content ([byte[]]$b[$cs..($b.Length - 1)])).Content
    $esl = Parse-Esl $content
    [pscustomobject]@{ Name = Split-Path -Leaf $Path; Content = $content; Certs = $esl.Certs; Hashes = $esl.Hashes; Other = $esl.Other; Valid = $esl.Valid }
}

function New-CertEsl([byte[]]$der) {
    $ms = New-Object IO.MemoryStream
    $w  = New-Object IO.BinaryWriter $ms
    $w.Write($X509Guid.ToByteArray())
    $w.Write([UInt32](28 + 16 + $der.Length))
    $w.Write([UInt32]0)
    $w.Write([UInt32](16 + $der.Length))
    $w.Write($MsOwnerGuid.ToByteArray())
    $w.Write($der)
    $w.Flush(); $ms.ToArray()
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

function Get-DbxSkipReason($p) {
    # $null = Hashes duerfen in die dbx, sonst der Grund fuers Ueberspringen
    if ($p.Name -match 'DBXUpdate2024')    { return 'PCA-2011-Sperre, NIE' }
    if (-not $p.Valid -or $p.Other -gt 0) { return 'Format nicht sauber erkannt' }
    if ($p.Certs.Count -gt 0)             { return 'enthaelt Zertifikate, z.B. PCA-2011-Sperre' }
    if ($p.Hashes -eq 0)                  { return 'keine Hashes' }
    $null
}

function Get-VarBytes([string]$Name) { try { (Get-SecureBootUEFI -Name $Name -ErrorAction Stop).Bytes } catch { $null } }
function Join-Bytes { param([object[]]$Parts) $l = New-Object System.Collections.Generic.List[byte]; foreach ($p in $Parts) { if ($p) { $l.AddRange([byte[]]$p) } }; ,$l.ToArray() }

function Get-ClearHint {
    $cs = Get-CimInstance Win32_ComputerSystem; $m = "$($cs.Manufacturer)"; $mo = "$($cs.Model)"
    if ($mo -match 'Virtual Machine' -and $m -match 'Microsoft') { return 'Hyper-V: nicht moeglich (Vorlage verwenden)' }
    if ($m -match 'VMware')      { return 'VMware: nicht noetig/anders (NVRAM)' }
    if ($m -match 'HP|Hewlett')  { return 'F10 -> Advanced (aeltere Modelle: Security) -> Secure Boot Configuration -> "Clear Secure Boot Keys" (Bestaetigungscode eingeben). Gibt es dort "Key Ownership", vorher auf "Custom Keys" stellen: mit "HP Keys" laden manche Firmwares (z.B. Compaq Pro 6300) nach dem Loeschen wieder die Werksschluessel statt in den Setup Mode zu gehen - siehe LIESMICH.' }
    if ($m -match 'Google' -or "$((Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion)" -match 'MrChromebox') { return 'Esc beim Start -> Device Manager -> Secure Boot Configuration -> Secure Boot Mode "Custom" -> Custom Secure Boot Options -> PK Options -> Delete PK' }
    if ($m -match 'Dell')        { return 'F2 -> Secure Boot -> Expert Key Management -> Custom Mode an -> "Delete All Keys"' }
    if ($m -match 'Lenovo')      { return 'F1/F2 -> Security -> Secure Boot -> "Reset to Setup Mode" bzw. "Clear All Secure Boot Keys"' }
    if ($m -match 'Fujitsu')     { return 'F2 -> Security -> Secure Boot Configuration -> "Delete all Secure Boot Variables" / Setup Mode' }
    if ($m -match 'ASUS|ASRock|Micro-Star|MSI|Gigabyte') { return 'Entf -> Boot -> Secure Boot -> Key Management -> "Clear Secure Boot Keys" / "Delete All Secure Boot Variables"' }
    'Firmware-Setup -> Secure Boot -> "Clear / Delete all keys" bzw. "Setup Mode"'
}

# ================================================================ Status
Section "Status"
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$model = "$($cs.Manufacturer) $($cs.Model)"
Info ("{0}, BIOS {1}" -f $model, $bios.SMBIOSBIOSVersion)
Info ("Skript-Version {0}, Geraet {1}" -f $ScriptVersion, $deviceId)
try { $null = Confirm-SecureBootUEFI -ErrorAction Stop } catch { Bad "Kein UEFI - Abbruch."; Finish }
$setupMode = $null
try { $setupMode = (Get-SecureBootUEFI -Name SetupMode).Bytes[0] } catch {}
if ($Restore)              { Info ("Modus: Sicherung zurueckspielen, Firmware im {0}" -f $(if ($setupMode -eq 1) { 'SETUP MODE' } else { 'User Mode' })) }
elseif ($setupMode -eq 1) { Warn "Firmware ist im SETUP MODE -> Phase 2 (Zurueckschreiben)" }
else                      { Info "Firmware ist im User Mode -> Phase 1 (Vorbereiten)" }
Info "Rebuild-Daten: $StateDir"

# ================================================================ SICHERUNG ZURUECKSPIELEN (7_)
if ($Restore) {
    Section "Sicherung zurueckspielen"
    # Kandidaten: Backups\<PC>\Backup_* (von 4_/5_) und Rebuild\<PC>\Original (von 6_), lokal und im Skriptordner
    $cands = @(); $seen = @{}
    foreach ($base in @($localDir, $scriptDir) | Select-Object -Unique) {
        foreach ($id in @($deviceId, $env:COMPUTERNAME) | Select-Object -Unique) {
            foreach ($kind in 'Backups','Rebuild') {
                $r = Join-Path (Join-Path $base $kind) $id
                if (-not (Test-Path $r)) { continue }
                foreach ($d in @(Get-ChildItem $r -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Backup_*' -or $_.Name -eq 'Original' })) {
                    $key = "$kind\$($d.Name)"
                    if ($seen.ContainsKey($key)) { continue }
                    $f = @{}
                    foreach ($n in 'PK','KEK','db','dbx') {
                        foreach ($ext in 'esl','bin') { $x = Join-Path $d.FullName "$n.$ext"; if (-not $f[$n] -and (Test-Path $x)) { $f[$n] = $x } }
                    }
                    if ($f['PK'] -and $f['KEK'] -and $f['db']) {
                        $seen[$key] = $true
                        $cands += [pscustomobject]@{ Label = $key; Dir = $d.FullName; Time = $d.LastWriteTime; Files = $f }
                    }
                }
            }
        }
    }
    $cands = @($cands | Sort-Object Time -Descending)
    if ($cands.Count -eq 0) { Bad "Keine Sicherung fuer dieses Geraet gefunden (Backups\$deviceId\ bzw. Rebuild\$deviceId\Original)."; Finish }

    for ($i = 0; $i -lt $cands.Count; $i++) {
        $c = $cands[$i]
        $k = Parse-Esl ([IO.File]::ReadAllBytes($c.Files['KEK']))
        $d = Parse-Esl ([IO.File]::ReadAllBytes($c.Files['db']))
        $x = if ($c.Files['dbx']) { Parse-Esl ([IO.File]::ReadAllBytes($c.Files['dbx'])) } else { $null }
        $kek23 = [bool]($k.Certs | Where-Object { $_.Subject -match 'KEK 2K CA 2023' })
        $win23 = [bool]($d.Certs | Where-Object { $_.Subject -match 'Windows UEFI CA 2023' })
        Write-Host ""
        Info ("[{0}]  {1}   ({2})" -f ($i + 1), $c.Label, $c.Time.ToString('yyyy-MM-dd HH:mm'))
        Info ("      KEK: {0} Zertifikate, KEK 2023: {1}" -f $k.Certs.Count, $(if ($kek23) { 'ja' } else { 'nein' }))
        Info ("      db:  {0} Zertifikate, Windows UEFI CA 2023: {1}" -f $d.Certs.Count, $(if ($win23) { 'ja' } else { 'nein' }))
        Info ("      dbx: {0}" -f $(if ($x) { "$($x.Hashes) Hashes" + $(if (-not $x.Valid) { ', BESCHAEDIGT (wird bereinigt)' } else { '' }) } else { 'nicht gesichert (bleibt leer)' }))
        if (-not $k.Valid -or -not $d.Valid) { Warn "      KEK oder db dieser Sicherung sind fehlerhaft - nicht verwendbar" }
    }
    Write-Host ""

    if ($setupMode -ne 1) {
        Warn "Die Firmware ist im User Mode. Zum Zurueckschreiben muss sie im Setup Mode sein:"
        Info ("  1. Neu starten, im Firmware-Setup die Schluessel loeschen: {0}" -f (Get-ClearHint))
        Info  "  2. Windows starten (falls noetig vorher Secure Boot aus)."
        Info  "  3. 7_Sicherung_zurueckspielen.cmd erneut ausfuehren und die Sicherung auswaehlen."
        Finish
    }

    $sel = Read-Host "Nummer der Sicherung, die zurueckgeschrieben werden soll (leer = Abbruch)"
    $n = 0
    if (-not [int]::TryParse("$sel", [ref]$n) -or $n -lt 1 -or $n -gt $cands.Count) { Info "Abgebrochen. Firmware bleibt im Setup Mode."; Finish }
    $c = $cands[$n - 1]
    $k = Parse-Esl ([IO.File]::ReadAllBytes($c.Files['KEK']))
    $d = Parse-Esl ([IO.File]::ReadAllBytes($c.Files['db']))
    if (-not $k.Valid -or -not $d.Valid) { Bad "KEK oder db dieser Sicherung sind fehlerhaft - Abbruch."; Finish }
    if (-not ($d.Certs | Where-Object { $_.Subject -match 'Windows UEFI CA 2023' })) {
        Warn "Diese Sicherung enthaelt die Windows UEFI CA 2023 NICHT."
        Info "Ist der Boot-Manager schon 2023-signiert, startet Windows danach mit eingeschaltetem Secure Boot nicht."
        Info "Dann Secure Boot ausgeschaltet lassen, Windows starten und 5_Manuell_mit_dbx.cmd ausfuehren."
    }

    # Auswahl in einen eigenen Arbeitsordner kopieren und mit Phase 2 schreiben
    $StateDir = Join-Path (Get-SubDir $localDir 'Restore') (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    foreach ($nm in 'PK','KEK','db','dbx') { if ($c.Files[$nm]) { Copy-Item $c.Files[$nm] (Join-Path $StateDir "$nm.esl") -Force } }
    "$env:COMPUTERNAME|$model|$($bios.SMBIOSBIOSVersion)|$($c.Time.ToString('s'))|$serial" | Set-Content (Join-Path $StateDir 'device.txt') -Encoding ASCII
    Info ("Gewaehlt: {0}" -f $c.Dir)
}

# ================================================================ PHASE 1
if ($setupMode -ne 1) {
    Section "Phase 1: Vorbereiten"
    $pk  = Get-VarBytes 'PK';  $kek = Get-VarBytes 'KEK'
    $db  = Get-VarBytes 'db';  $dbx = Get-VarBytes 'dbx'
    if (-not $pk -or -not $kek -or -not $db) { Bad "PK/KEK/db nicht lesbar - Abbruch."; Finish }
    # Erkennen: Wurden seit dem letzten Phase-1-Lauf die WERKSSCHLUESSEL geladen statt Setup Mode?
    $origDbFile = Join-Path $StateDir 'Original\db.esl'
    if (Test-Path $origDbFile) {
        $origDb = Parse-Esl ([IO.File]::ReadAllBytes($origDbFile))
        $nowDb  = Parse-Esl $db
        $lost = @($origDb.Certs | Where-Object { $t = $_.Thumbprint; -not ($nowDb.Certs | Where-Object { $_.Thumbprint -eq $t }) })
        if ($lost.Count -gt 0) {
            Bad "Seit dem letzten Lauf sind Eintraege aus der db VERSCHWUNDEN:"
            foreach ($c in $lost) { Info ("  - {0}" -f (Get-CN $c.Subject)) }
            Bad "Die Firmware hat beim 'Schluessel loeschen' offenbar die WERKSSCHLUESSEL geladen statt in den Setup Mode zu gehen."
            Info "Auf diesem Geraet funktioniert der Setup-Mode-Weg so NICHT."
            if ($model -match 'HP|Hewlett') {
                Info "HP: Gibt es im Firmware-Setup unter Secure Boot Configuration die Einstellung 'Key Ownership',"
                Info "    vor dem naechsten Versuch auf 'Custom Keys' statt 'HP Keys' stellen. Mit 'HP Keys' laedt die"
                Info "    Firmware nach dem Loeschen moeglicherweise immer wieder ihre Werksschluessel."
            }
            Info "Wiederherstellen:  (falls Windows nicht startet: Secure Boot im Firmware-Setup AUS)"
            Info "  1. 5_Manuell_mit_dbx.cmd   (traegt die 2023-CAs und die dbx wieder ein)"
            Info "  2. Secure Boot wieder AN, neu starten, 1_Pruefen.cmd"
            Info ("Die alten Rebuild-Daten bleiben unveraendert in {0}." -f $StateDir)
            Finish
        }
    }
    $pkE = Parse-Esl $pk; $kekE = Parse-Esl $kek; $dbE = Parse-Esl $db; $dbxE = Parse-Esl $dbx
    Info ("PK:  {0}" -f (($pkE.Certs | ForEach-Object { Get-CN $_.Subject }) -join ', '))
    if ($pkE.Certs | Where-Object { $_.Subject -match 'DO NOT TRUST|DO NOT SHIP' }) {
        Bad "PK ist ein Testschluessel (PKfail). Den wuerde dieses Skript 1:1 zurueckschreiben - Abbruch."
        Finish
    }
    if (-not (Test-Path $PayloadDir)) { Bad "Ordner $PayloadDir fehlt - Windows aktualisieren oder -PayloadDir angeben."; Finish }

    # --- KEK
    $kekAdd = $null
    if ($kekE.Certs | Where-Object { $_.Subject -match 'KEK 2K CA 2023' }) { Ok "KEK 2023 ist schon vorhanden" }
    else {
        $blob = Join-Path $PayloadDir 'KEKUpdateCombined.bin'
        $msKek = $null
        if (Test-Path $blob) { Info "Suche Microsoft KEK 2023 in KEKUpdateCombined.bin ..."; $msKek = Find-CertInBlob ([IO.File]::ReadAllBytes($blob)) 'KEK 2K CA 2023' }
        if (-not $msKek) {
            foreach ($f in Get-ChildItem $PayloadDir -File -ErrorAction SilentlyContinue) {
                $msKek = Find-CertInBlob ([IO.File]::ReadAllBytes($f.FullName)) 'KEK 2K CA 2023'
                if ($msKek) { break }
            }
        }
        if ($msKek -and $msKek.Subject -match 'CN=Microsoft Corporation KEK 2K CA 2023') {
            Ok ("Gefunden: {0} (Aussteller {1}, gueltig bis {2:yyyy-MM-dd})" -f (Get-CN $msKek.Subject), (Get-CN $msKek.Issuer), $msKek.NotAfter)
            $kekAdd = New-CertEsl $msKek.RawData
        } else { Warn "Microsoft KEK 2023 nicht gefunden - KEK bleibt wie er ist" }
    }
    $newKek = Join-Bytes @($kek, $kekAdd)

    # --- db
    $dbAdds = @()
    $have = @{}; foreach ($c in $dbE.Certs) { $have[$c.Thumbprint] = $true }
    $payloads = @(Get-ChildItem $PayloadDir -Filter *.bin -File -ErrorAction SilentlyContinue | ForEach-Object { Read-AuthPayload $_.FullName } | Where-Object { $_ })
    foreach ($p in $payloads | Where-Object { $_.Name -notmatch 'dbx|kek' -and $_.Valid -and $_.Other -eq 0 -and $_.Certs.Count -gt 0 }) {
        $missing = @($p.Certs | Where-Object { -not $have.ContainsKey($_.Thumbprint) })
        if ($missing.Count -gt 0) {
            Info ("db + {0}  [{1}]" -f (($missing | ForEach-Object { Get-CN $_.Subject }) -join ', '), $p.Name)
            $dbAdds += ,$p.Content
            foreach ($c in $p.Certs) { $have[$c.Thumbprint] = $true }
        }
    }
    if ($dbAdds.Count -eq 0) { Ok "db hat bereits alle 2023-CAs" }
    $newDb = Join-Bytes (@(,$db) + $dbAdds)

    # --- dbx
    $dbxAdds = @()
    foreach ($p in $payloads | Where-Object { $_.Name -match 'dbx' }) {
        $why = Get-DbxSkipReason $p
        if ($why) { if ($why -ne 'keine Hashes') { Info ("dbx: {0} uebersprungen ({1})" -f $p.Name, $why) }; continue }
        Info ("dbx + {0} Hashes  [{1}]" -f $p.Hashes, $p.Name)
        $dbxAdds += ,$p.Content
    }
    $newDbx = Get-CleanDbx (Join-Bytes (@(,$dbx) + $dbxAdds))
    foreach ($chk in @(@('KEK',$newKek), @('db',$newDb), @('dbx',$newDbx))) {
        if (-not (Parse-Esl $chk[1]).Valid) { Bad ("Neuer {0}-Inhalt ist fehlerhaft - Abbruch, nichts gespeichert." -f $chk[0]); Finish }
    }

    # --- Zusammenfassung
    $nk = Parse-Esl $newKek; $nd = Parse-Esl $newDb; $nx = Parse-Esl $newDbx
    Section "Neuer Inhalt (wird in Phase 2 geschrieben)"
    Info "KEK: $((($nk.Certs | ForEach-Object { Get-CN $_.Subject }) -join ', '))"
    Info "db:  $((($nd.Certs | ForEach-Object { Get-CN $_.Subject }) -join ', '))"
    Info ("dbx: {0} Hashes (vorher {1})" -f $nx.Hashes, $dbxE.Hashes)
    Info "PK:  unveraendert"

    if (-not ($nd.Certs | Where-Object { $_.Subject -match 'Windows UEFI CA 2023' })) { Warn "db haette keine Windows UEFI CA 2023 - pruefen!" }
    if (-not ($nd.Certs | Where-Object { $_.Subject -match 'Windows Production PCA 2011' })) { Warn "db haette keine PCA 2011 - aeltere Boot-Medien wuerden nicht starten" }

    if (-not $kekAdd -and $dbAdds.Count -eq 0 -and $dbxAdds.Count -eq 0) { Ok "Nichts zu ergaenzen."; Finish }

    Write-Host ""
    if (-not (Confirm-JA "Rebuild-Daten speichern und Phase 1 abschliessen?")) { Info "Abgebrochen."; Finish }

    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $StateDir 'PK.esl'),  $pk)
    [IO.File]::WriteAllBytes((Join-Path $StateDir 'KEK.esl'), $newKek)
    [IO.File]::WriteAllBytes((Join-Path $StateDir 'db.esl'),  $newDb)
    [IO.File]::WriteAllBytes((Join-Path $StateDir 'dbx.esl'), $newDbx)
    $bk = Join-Path $StateDir 'Original'; New-Item -ItemType Directory -Path $bk -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $bk 'PK.esl'), $pk);   [IO.File]::WriteAllBytes((Join-Path $bk 'KEK.esl'), $kek)
    [IO.File]::WriteAllBytes((Join-Path $bk 'db.esl'), $db);   if ($dbx) { [IO.File]::WriteAllBytes((Join-Path $bk 'dbx.esl'), $dbx) }
    "$env:COMPUTERNAME|$model|$($bios.SMBIOSBIOSVersion)|$(Get-Date -Format s)|$serial" | Set-Content (Join-Path $StateDir 'device.txt') -Encoding ASCII
    Ok "Gespeichert in $StateDir"
    if (-not $sameDir) {
        # Inhalt von Rebuild\<PC>\ nach <Skriptordner>\Rebuild\<PC>\
        try { $dest = Get-SubDir $scriptDir 'Rebuild'; Copy-Item -Path (Join-Path $StateDir '*') -Destination $dest -Recurse -Force -ErrorAction Stop; Ok "Kopie im Skriptordner: $dest" } catch { Warn "Kopie in den Skriptordner fehlgeschlagen: $_" }
    }

    try {
        $blv = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ($blv.ProtectionStatus -eq 'On') { Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 3 -ErrorAction Stop | Out-Null; Ok "BitLocker fuer 3 Neustarts angehalten" }
    } catch {}

    Section "Naechste Schritte"
    Info "1. Neu starten und ins Firmware-Setup gehen:"
    Info ("   {0}" -f (Get-ClearHint))
    Info "   Secure Boot selbst NICHT ausschalten (falls das Setup es verlangt, ist es auch ok)."
    Info "2. Windows starten (im Setup Mode wird Secure Boot nicht erzwungen, Windows startet normal)."
    Info "3. Dieses Skript ERNEUT ausfuehren -> Phase 2."
    Write-Host ""
    Warn "Startet Windows nach dem Loeschen NICHT: Secure Boot im Firmware-Setup ausschalten, booten, Skript ausfuehren."
    Finish
}

# ================================================================ PHASE 2
Section "Phase 2: Zurueckschreiben"
if (-not (Test-Path (Join-Path $StateDir 'PK.esl'))) {
    Bad "Keine Rebuild-Daten in $StateDir gefunden."
    Info "Kopie vom Stick angeben:  -StateDir <Stick>\Rebuild\$deviceId"
    Info "Oder im Firmware-Setup die Schluessel auf Werkseinstellung zuruecksetzen."
    Finish
}
$dev = (Get-Content (Join-Path $StateDir 'device.txt') -ErrorAction SilentlyContinue) -split '\|'
$idMismatch = if ($dev.Count -ge 5 -and $dev[4] -and $serial) { $dev[4] -ne $serial } else { $dev[0] -ne $env:COMPUTERNAME }
if ($dev.Count -ge 2 -and ($idMismatch -or $dev[1] -ne $model)) {
    Bad ("Rebuild-Daten gehoeren zu '{0}' ({1}), nicht zu diesem Geraet - Abbruch." -f $dev[0], $dev[1]); Finish
}
Info ("Daten vom {0}" -f $dev[3])

# Schutz vor fehlerhaften Daten aus aelteren Skriptversionen
foreach ($f in 'PK.esl','KEK.esl','db.esl') {
    if (-not (Parse-Esl ([IO.File]::ReadAllBytes((Join-Path $StateDir $f)))).Valid) {
        Bad "$f ist fehlerhaft - Abbruch. Rebuild-Ordner loeschen und Phase 1 neu durchlaufen."; Finish
    }
}
$dbxPath = Join-Path $StateDir 'dbx.esl'
if (Test-Path $dbxPath) {
    $dbxRaw = [IO.File]::ReadAllBytes($dbxPath)
    # Beim Neuaufbau bleiben nur Hash-Sperren; beim Zurueckspielen wird nur bereinigt, wenn die Datei beschaedigt ist
    if (-not $Restore -or -not (Parse-Esl $dbxRaw).Valid) {
        $dbxOk = Get-CleanDbx $dbxRaw
        if ($dbxOk.Length -ne $dbxRaw.Length) {
            Warn ("dbx.esl enthielt fehlerhafte/unerwuenschte Teile ({0} -> {1} Bytes) - bereinigt, nur Hash-Sperren bleiben." -f $dbxRaw.Length, $dbxOk.Length)
            [IO.File]::WriteAllBytes($dbxPath, $dbxOk)
        }
    }
    if ((Get-Item $dbxPath).Length -eq 0) { Remove-Item $dbxPath -Force }
}

$steps = @(@{ Name = 'db'; File = 'db.esl'; Critical = $true })
if (Test-Path $dbxPath) { $steps += @{ Name = 'dbx'; File = 'dbx.esl'; Critical = $false } }
$steps += @{ Name = 'KEK'; File = 'KEK.esl'; Critical = $true }
foreach ($s in $steps) {
    $e = Parse-Esl ([IO.File]::ReadAllBytes((Join-Path $StateDir $s.File)))
    $what = if ($e.Certs.Count) { ($e.Certs | ForEach-Object { Get-CN $_.Subject }) -join ', ' } else { '' }
    Info ("{0,-4}: {1} {2}" -f $s.Name, $what, $(if ($e.Hashes) { "+ $($e.Hashes) Hashes" } else { '' }))
}
Info "PK  : (Original des Herstellers) - wird ZULETZT geschrieben"
Write-Host ""
if (-not (Confirm-JA "Jetzt db, dbx, KEK und PK in die Firmware schreiben?")) { Info "Abgebrochen. Firmware bleibt im Setup Mode."; Finish }

try {
    $blv = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($blv.ProtectionStatus -eq 'On') { Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 3 -ErrorAction Stop | Out-Null; Ok "BitLocker fuer 3 Neustarts angehalten" }
} catch {}

function Write-Var([string]$Name, [string]$File) {
    $path = Join-Path $StateDir $File
    $want = [IO.File]::ReadAllBytes($path)
    try {
        Set-SecureBootUEFI -Name $Name -Time $WriteTime -ContentFilePath $path -ErrorAction Stop | Out-Null
    } catch { Bad ("{0}: Schreiben fehlgeschlagen: {1}" -f $Name, $_.Exception.Message); return $false }
    $got = Get-VarBytes $Name
    if (-not $got) { Bad "${Name}: nach dem Schreiben nicht lesbar"; return $false }
    $gw = Parse-Esl $want; $gg = Parse-Esl $got
    $missing = @($gw.Certs | Where-Object { $t = $_.Thumbprint; -not ($gg.Certs | Where-Object { $_.Thumbprint -eq $t }) })
    if ($missing.Count -gt 0 -or ($gw.Hashes -gt 0 -and $gg.Hashes -eq 0)) {
        Bad ("{0}: geschrieben, aber Inhalt unvollstaendig ({1} Bytes)" -f $Name, $got.Length); return $false
    }
    Ok ("{0} geschrieben ({1} Bytes, {2} Zertifikate, {3} Hashes)" -f $Name, $got.Length, $gg.Certs.Count, $gg.Hashes)
    $true
}

$critOk = $true
foreach ($s in $steps) {
    $r = Write-Var $s.Name $s.File
    if (-not $r -and $s.Critical) { $critOk = $false }
    if (-not $r -and -not $s.Critical) { Warn "$($s.Name) fehlgeschlagen - nicht kritisch, es geht weiter." }
}

if (-not $critOk) {
    Bad "db oder KEK konnten nicht geschrieben werden - PK wird NICHT geschrieben."
    Info "Die Firmware bleibt im Setup Mode (Windows startet, Secure Boot wird nicht erzwungen)."
    Info "Optionen: Skript erneut ausfuehren, oder im Firmware-Setup Schluessel auf Werkseinstellung"
    Info "+ Secure Boot aus, booten, 4_Manuell_einspielen.cmd, Secure Boot wieder an."
    Finish
}

$r = Write-Var 'PK' 'PK.esl'
$setupMode = $null; try { $setupMode = (Get-SecureBootUEFI -Name SetupMode).Bytes[0] } catch {}
if ($r -and $setupMode -eq 0) {
    Ok "PK geschrieben - Firmware ist wieder im USER MODE"
} elseif ($r) {
    Ok "PK geschrieben und zurueckgelesen."
    Info "Die Firmware meldet noch 'Setup Mode' - manche (z.B. Lenovo ThinkCentre M93) wechseln erst"
    Info "nach dem Neustart in den User Mode. Bis dahin keine anderen Skripte starten."
} else {
    Warn "Die Firmware hat den Original-PK abgelehnt."
    Info "Viele Firmwares verlangen, dass ein PK mit seinem eigenen privaten Schluessel signiert ist -"
    Info "den hat nur der Hersteller. Das laesst sich von Windows aus NICHT loesen, erneutes Ausfuehren hilft nicht."
    Info ""
    Info "Was jetzt passiert, haengt von der Firmware ab:"
    Info " - Manche (z.B. HP ProDesk 400 G5, EliteBook 840 G3) tragen beim naechsten Start ihren Werks-PK"
    Info "   selbst wieder ein. KEK und db bleiben dabei erhalten, die dbx faellt auf Werkseinstellung zurueck."
    Info "   Dann: 5_Manuell_mit_dbx.cmd (dbx), 2_Update_anstossen.cmd (Windows uebernimmt den Stand, 1808),"
    Info "   neu starten, 1_Pruefen.cmd."
    Info " - Andere bleiben im Setup Mode: Windows startet, Secure Boot wird aber NICHT erzwungen."
    Info ""
    Info "-> NEU STARTEN und 1_Pruefen.cmd laufen lassen."
    Info "   Steht dort 'Setup Mode': im Firmware-Setup nach 'PK wiederherstellen' / 'Restore PK' /"
    Info "   'Install default PK' suchen. Gibt es das nicht: Schluessel auf Werkseinstellung + Secure Boot aus,"
    Info "   booten, 4_Manuell_einspielen.cmd, Secure Boot wieder an (KEK 2023 ist dann wieder weg)."
    Finish
}

Section "Fertig"
Info "1. NEU STARTEN. Falls im Firmware-Setup Secure Boot ausgegangen ist: wieder einschalten."
Info "2. 1_Pruefen.cmd laufen lassen - KEK 2023, db und dbx sollten gruen sein."
Info "3. Optional 2_Update_anstossen.cmd, damit Windows den Stand uebernimmt (AvailableUpdates -> 0)."
Finish
