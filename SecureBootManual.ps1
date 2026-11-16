<#
.SYNOPSIS
    Secure-Boot-2023-Zertifikate VON HAND per Set-SecureBootUEFI einspielen
    (umgeht die Microsoft-Sperre "Firmware_KI" / Ereignis 1802).

.DESCRIPTION
    ACHTUNG: Microsoft sperrt das automatische Update auf manchen Geraeten, weil
    ein Firmwarefehler bekannt ist. Dieses Skript schreibt trotzdem. Im schlimmsten
    Fall bootet der PC danach nicht mehr mit aktivem Secure Boot.
    RETTUNG: Firmware-Setup (BIOS/UEFI) -> Secure Boot -> Schluessel auf Werkseinstellung
             zuruecksetzen ODER Secure Boot aus. Das Skript zeigt den typischen Weg
             fuer den erkannten Hersteller (HP, Dell, Lenovo, Fujitsu, Surface, ...).

    Ablauf:
      1. Sicherung von PK, KEK, db, dbx in C:\ProgramData\SecureBootCheck\Backups\<PC>\Backup_<Zeit>\
         (und Kopie in den Skriptordner)
      2. Durchsucht die von Windows mitgelieferten, von Microsoft signierten
         Update-Dateien (C:\Windows\System32\SecureBootUpdates\*.bin) oder -PayloadDir
      3. Zerlegt jede Datei (Zeitstempel / Signatur / Inhalt), zeigt welches Zertifikat
         drin steckt und wohin es gehoert (db / KEK / dbx)
      4. Ohne -Execute: nur anzeigen (Trockenlauf)
         Mit  -Execute: jeden Schritt einzeln mit "JA" bestaetigen, dann schreiben

    Reihenfolge: db (Windows UEFI CA 2023 zuerst), danach KEK, dbx nur mit -IncludeDbx.
    Der KEK-Schritt klappt nur, wenn die Datei mit dem PK DIESES Geraets (Hersteller) signiert
    ist - sonst lehnt die Firmware ab (harmlos).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\SecureBootManual.ps1              # Trockenlauf
    powershell -ExecutionPolicy Bypass -File .\SecureBootManual.ps1 -Execute     # wirklich schreiben
#>
[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$IncludeDbx,
    [string]$PayloadDir = "$env:SystemRoot\System32\SecureBootUpdates",
    [switch]$NoPause
)

# ---------------------------------------------------------------- Admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($Execute)    { $argList += '-Execute' }
    if ($IncludeDbx) { $argList += '-IncludeDbx' }
    if ($NoPause)    { $argList += '-NoPause' }
    $argList += @('-PayloadDir', "`"$PayloadDir`"")
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

$scriptDir = Split-Path -Parent $PSCommandPath
$stamp     = Get-Date -Format 'yyyy-MM-dd_HH-mm'

# Protokoll zuerst LOKAL schreiben (ueberlebt abgezogenen Stick), am Ende in den Skriptordner kopieren
$localDir  = Join-Path $env:ProgramData 'SecureBootCheck'
# Ordnerstruktur (lokal und im Skriptordner gleich):  Logs\<PC>\   Backups\<PC>\   Rebuild\<PC>\
function Get-SubDir([string]$Root, [string]$Kind) { $d = Join-Path (Join-Path $Root $Kind) $env:COMPUTERNAME; New-Item -ItemType Directory -Path $d -Force -ErrorAction SilentlyContinue | Out-Null; $d }
$sameDir   = ($scriptDir.TrimEnd('\') -eq $localDir.TrimEnd('\'))
function Copy-ToScriptDir([string]$Path, [string]$Kind) {
    # Kopiert eine Datei/einen Ordner aus dem lokalen <Kind>\<PC>\ in den gleichen Unterordner im Skriptordner
    if ($sameDir -or -not (Test-Path $Path)) { return $null }
    try { $dest = Get-SubDir $scriptDir $Kind; Copy-Item -Path $Path -Destination $dest -Recurse -Force -ErrorAction Stop; $dest } catch { $null }
}
$logFile   = Join-Path (Get-SubDir $localDir 'Logs') ("{0}_{1}_{2}.txt" -f 'SecureBootManual', $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd_HH-mm'))
try { Start-Transcript -Path $logFile -Force | Out-Null } catch { Write-Warning "Kein Protokoll moeglich: $_" }
function Copy-LogToScriptDir {
    try { Stop-Transcript | Out-Null } catch {}
    $d = Copy-ToScriptDir $logFile 'Logs'
    if ($d) { Write-Host "         Protokoll kopiert nach: $d" -ForegroundColor DarkGray }
    elseif (-not $sameDir) { Write-Host "         Kopieren in den Skriptordner fehlgeschlagen" -ForegroundColor Yellow }
    Write-Host "         Lokales Protokoll:      $logFile" -ForegroundColor DarkGray
    Write-Host "         Stick vor dem Abziehen bitte 'sicher entfernen'." -ForegroundColor DarkGray
}

function Get-VendorInfo {
    # Typische Wege zum Zuruecksetzen der Secure-Boot-Schluessel - je nach Modell/BIOS-Version abweichend
    $cs = Get-CimInstance Win32_ComputerSystem
    $m = "$($cs.Manufacturer)"; $mo = "$($cs.Model)"
    $v = [pscustomobject]@{ Vendor = $m.Trim(); Key = 'F2, F10, F1 oder Entf'; Reset = 'Secure Boot -> Schluessel auf Werkseinstellung (Restore Factory / Default Keys)'; Extra = '' }
    if ($mo -match 'Virtual Machine' -and $m -match 'Microsoft') {
        $v.Vendor = 'Hyper-V'; $v.Key = '(VM ausgeschaltet) Hyper-V-Manager'; $v.Reset = 'VM-Einstellungen -> Sicherheit -> Secure Boot aus, oder VM mit neuer Vorlage neu anlegen'
    } elseif ($m -match 'VMware') {
        $v.Vendor = 'VMware'; $v.Key = '(VM ausgeschaltet) VM-Einstellungen'; $v.Reset = 'VM Options -> Boot Options -> Secure Boot aus; NVRAM-Datei (.nvram) loeschen setzt die Schluessel zurueck'
    } elseif ($m -match 'HP|Hewlett') {
        $v.Vendor = 'HP'; $v.Key = 'F10'; $v.Reset = 'Advanced (aeltere Modelle: Security) -> Secure Boot Configuration -> Secure-Boot-Schluessel auf Werkseinstellung zuruecksetzen'; $v.Extra = 'Falls vorhanden: "Sure Start Secure Boot Keys Protection" deaktivieren.'
    } elseif ($m -match 'Dell') {
        $v.Vendor = 'Dell'; $v.Key = 'F2'; $v.Reset = 'Secure Boot -> Expert Key Management -> Restore Settings (Factory)'
    } elseif ($m -match 'Lenovo') {
        $v.Vendor = 'Lenovo'; $v.Key = 'F1 (ThinkPad/ThinkCentre) bzw. F2 / Novo-Taste (IdeaPad)'; $v.Reset = 'Security -> Secure Boot -> Restore Factory Keys'
    } elseif ($m -match 'Fujitsu') {
        $v.Vendor = 'Fujitsu'; $v.Key = 'F2'; $v.Reset = 'Security -> Secure Boot Configuration -> Restore Factory Keys'
    } elseif ($m -match 'Microsoft' -and $mo -match 'Surface') {
        $v.Vendor = 'Microsoft Surface'; $v.Key = 'Lauter-Taste beim Einschalten halten'; $v.Reset = 'Security -> Secure Boot -> Microsoft Only / Default'
    } elseif ($m -match 'ASUS|ASRock|Micro-Star|MSI|Gigabyte') {
        $v.Key = 'Entf / F2'; $v.Reset = 'Boot -> Secure Boot -> Key Management -> Restore Factory Keys / Install Default Secure Boot Keys'
    } elseif ($m -match 'Google' -or "$((Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion)" -match 'MrChromebox') {
        $v.Vendor = 'Chromebox/Chromebook (MrChromebox-UEFI)'; $v.Key = 'Esc beim Start'; $v.Reset = 'Device Manager -> Secure Boot Configuration -> Reset Secure Boot Keys'
    } elseif ($m -match 'Acer') {
        $v.Vendor = 'Acer'; $v.Key = 'F2'; $v.Reset = 'Security -> Restore Secure Boot to Factory Default (ggf. erst Supervisor-Passwort setzen)'
    }
    $v
}
$vi = Get-VendorInfo

function Section([string]$t) { Write-Host ""; Write-Host ("=" * 70) -ForegroundColor DarkCyan; Write-Host " $t" -ForegroundColor Cyan; Write-Host ("=" * 70) -ForegroundColor DarkCyan }
function Ok([string]$t)   { Write-Host "  [OK]   $t" -ForegroundColor Green }
function Bad([string]$t)  { Write-Host "  [!!]   $t" -ForegroundColor Red }
function Warn([string]$t) { Write-Host "  [??]   $t" -ForegroundColor Yellow }
function Info([string]$t) { Write-Host "         $t" }
function Finish {
    if ($backupDir) { $d = Copy-ToScriptDir $backupDir 'Backups'; if ($d) { Write-Host "         Sicherung kopiert nach: $d" -ForegroundColor DarkGray } }
    Copy-LogToScriptDir
    if (-not $NoPause) { Write-Host ""; Read-Host "Enter zum Beenden" | Out-Null }; exit }

Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
$X509Guid   = [Guid]'a5c059a1-94e4-4aa7-87b5-ab155c2bf072'
$Sha256Guid = [Guid]'c1c41626-504c-4092-aca9-41f936934328'
$Pkcs7Guid  = [Guid]'4aafd29d-68df-49ee-8aa9-347d375665a7'

function Get-CN([string]$dn) { if ($dn -match 'CN=([^,]+)') { $Matches[1].Trim() } else { $dn } }

function Parse-Esl([byte[]]$b) {
    # EFI_SIGNATURE_LIST(s) -> Zertifikate + Anzahl Hashes
    $certs = @(); $hashes = 0; $o = 0
    if (-not $b) { return [pscustomobject]@{ Certs=@(); Hashes=0 } }
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
            } elseif ($type -eq $Sha256Guid) { $hashes++ }
            $p += $sigSize
        }
        $o += $listSize
    }
    [pscustomobject]@{ Certs = $certs; Hashes = $hashes }
}

function Get-VarEsl([string]$Name) {
    try { Parse-Esl (Get-SecureBootUEFI -Name $Name -ErrorAction Stop).Bytes } catch { $null }
}

function Get-Signers([byte[]]$sig) {
    # PKCS7 aus EFI_VARIABLE_AUTHENTICATION_2: oft nacktes SignedData ohne ContentInfo -> ggf. einpacken
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    try { $cms.Decode($sig) } catch {
        try {
            $oid = [byte[]](0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02)
            function DerLen([int]$n) { if ($n -lt 128) { ,[byte[]]@($n) } elseif ($n -lt 256) { ,[byte[]]@(0x81,$n) } else { ,[byte[]]@(0x82, ($n -shr 8), ($n -band 0xFF)) } }
            $a0  = [byte[]](@(0xA0) + (DerLen $sig.Length) + $sig)
            $seq = [byte[]]($oid + $a0)
            $ci  = [byte[]](@(0x30) + (DerLen $seq.Length) + $seq)
            $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
            $cms.Decode($ci)
        } catch { return @() }
    }
    @($cms.SignerInfos | ForEach-Object { if ($_.Certificate) { Get-CN $_.Certificate.Subject } })
}

function Read-AuthPayload([string]$Path) {
    # EFI_VARIABLE_AUTHENTICATION_2 = EFI_TIME(16) + WIN_CERTIFICATE_UEFI_GUID + Inhalt
    $b = [IO.File]::ReadAllBytes($Path)
    if ($b.Length -lt 48) { return $null }
    $year = [BitConverter]::ToUInt16($b, 0)
    $dwLength = [BitConverter]::ToUInt32($b, 16)
    $certType = [BitConverter]::ToUInt16($b, 22)
    if ($year -lt 2000 -or $year -gt 2100 -or $certType -ne 0x0EF1) { return $null }
    $guid = New-Object Guid (,[byte[]]$b[24..39])
    if ($guid -ne $Pkcs7Guid) { return $null }
    $contentStart = 16 + $dwLength
    if ($contentStart -ge $b.Length) { return $null }
    try { $dt = New-Object DateTime ($year, $b[2], $b[3], $b[4], $b[5], $b[6]) } catch { return $null }
    $sig     = [byte[]]$b[40..($contentStart - 1)]
    $content = [byte[]]$b[$contentStart..($b.Length - 1)]
    $esl     = Parse-Esl $content
    [pscustomobject]@{
        File    = $Path
        Name    = Split-Path -Leaf $Path
        Time    = $dt.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        Sig     = $sig
        Content = $content
        Certs   = $esl.Certs
        Hashes  = $esl.Hashes
        Signers = Get-Signers $sig
    }
}

# ================================================================ Vorpruefung
Section "Vorpruefung"
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
Info ("{0} {1}, BIOS {2}" -f $cs.Manufacturer, $cs.Model, $bios.SMBIOSBIOSVersion)
Info ("Notfall-Weg ({0}): Taste {1} -> Secure Boot AUS (sicher)  bzw.  {2}" -f $vi.Vendor, $vi.Key, $vi.Reset)
Info  "  Schluessel-Reset nur, solange der Boot-Manager noch 2011-signiert ist - sonst danach kein Start mit Secure Boot."
try { $sbOn = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sbOn = $null }
if ($null -eq $sbOn) { Bad "Kein UEFI - Abbruch."; Finish }
if ($sbOn) { Ok "Secure Boot aktiv" } else { Warn "Secure Boot ist AUS (Schreiben geht trotzdem, sofern nicht Setup Mode)" }
try { if ((Get-SecureBootUEFI -Name SetupMode).Bytes[0] -eq 1) { Bad "Firmware im Setup Mode - erst Schluessel im BIOS auf Werkseinstellung setzen. Abbruch."; Finish } } catch {}

if (-not (Test-Path $PayloadDir)) {
    Bad "Ordner $PayloadDir nicht gefunden."
    Info "Entweder alle Windows-Updates installieren (der Ordner kommt mit den Secure-Boot-Updates),"
    Info "oder die signierten .bin-Dateien von Microsoft (GitHub: microsoft/secureboot_objects)"
    Info "in einen Ordner legen und mit -PayloadDir <Ordner> angeben."
    Finish
}
Info "Update-Dateien aus: $PayloadDir"

# ================================================================ Backup
Section "Sicherung der aktuellen Schluessel"
$backupDir = Join-Path (Get-SubDir $localDir 'Backups') ("Backup_{0}" -f $stamp)
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
foreach ($n in 'PK','KEK','db','dbx') {
    try {
        $v = Get-SecureBootUEFI -Name $n -ErrorAction Stop
        [IO.File]::WriteAllBytes((Join-Path $backupDir "$n.bin"), $v.Bytes)
        Ok ("{0,-4} gesichert ({1} Bytes)" -f $n, $v.Bytes.Length)
    } catch { Warn "$n konnte nicht gesichert werden: $_" }
}
Info "Ordner: $backupDir"

$db  = Get-VarEsl 'db'
$kek = Get-VarEsl 'KEK'
$dbx = Get-VarEsl 'dbx'
$have = @{}
foreach ($c in @($db.Certs) + @($kek.Certs)) { if ($c) { $have[$c.Thumbprint] = $true } }

# ================================================================ Dateien analysieren
Section "Gefundene, von Microsoft signierte Update-Dateien"
$plan = @()
$planned = @{}
foreach ($f in Get-ChildItem -Path $PayloadDir -Filter *.bin -File -ErrorAction SilentlyContinue) {
    $p = Read-AuthPayload $f.FullName
    if (-not $p) { Info ("{0}: kein signiertes Variablen-Update, uebersprungen" -f $f.Name); continue }

    # Ziel: zuerst nach Dateiname (DBX-Dateien koennen auch ZERTIFIKATE enthalten = Sperrung!), dann nach Inhalt
    if     ($p.Name -match 'dbx')                                     { $target = 'dbx' }
    elseif ($p.Name -match 'kek')                                     { $target = 'KEK' }
    elseif ($p.Certs | Where-Object { $_.Subject -match 'KEK' })      { $target = 'KEK' }
    elseif ($p.Certs.Count -gt 0)                                     { $target = 'db'  }
    elseif ($p.Hashes -gt 0)                                          { $target = 'dbx' }
    else                                                              { $target = '?'   }

    $what = if ($p.Certs.Count) { ($p.Certs | ForEach-Object { Get-CN $_.Subject }) -join ', ' } else { "$($p.Hashes) Hashes" }
    $missing = @($p.Certs | Where-Object { -not $have.ContainsKey($_.Thumbprint) })
    $signer = if ($p.Signers.Count) { $p.Signers -join ', ' } else { '(unbekannt)' }

    Write-Host ""
    Info ("Datei:      {0}" -f $p.Name)
    Info ("Inhalt:     {0}" -f $what)
    Info ("Ziel:       {0}" -f $target)
    Info ("Signiert:   {0}  ({1})" -f $signer, $p.Time)

    $certKey = (@($p.Certs | ForEach-Object { $_.Thumbprint }) | Sort-Object) -join ','

    $skip = $null
    if ($target -eq '?') { $skip = 'Inhalt nicht erkannt' }
    elseif ($target -eq 'dbx' -and ($p.Certs | Where-Object { $_.Subject -match 'Production PCA 2011' })) {
        $skip = 'SPERRT die alte Windows-CA 2011 - wird von diesem Skript NIE eingespielt (aktueller Boot-Manager und alle aelteren Boot-Medien wuerden nicht mehr starten)'
    }
    elseif ($target -eq 'dbx' -and $p.Certs.Count -gt 0) { $skip = 'dbx mit Zertifikaten - zu riskant, nicht automatisch' }
    elseif ($target -eq 'dbx' -and -not $IncludeDbx) { $skip = 'dbx nur mit -IncludeDbx (5_Manuell_mit_dbx.cmd)' }
    elseif ($target -ne 'dbx' -and $missing.Count -eq 0) { $skip = 'bereits vorhanden' }
    elseif ($target -ne 'dbx' -and $planned.ContainsKey($certKey)) {
        $planned[$certKey].Payloads += $p
        Info "-> Ersatzdatei (wird probiert, falls die erste abgelehnt wird)"
        continue
    }

    if ($target -eq 'KEK' -and -not $skip) {
        $pkSubj = @()
        try { $pkSubj = @((Parse-Esl (Get-SecureBootUEFI -Name PK).Bytes).Certs | ForEach-Object { Get-CN $_.Subject }) } catch {}
        Info ("PK dieses PCs: {0}" -f ($pkSubj -join ', '))
        Warn "KEK-Update klappt nur, wenn die Datei mit genau diesem PK signiert ist."
    }

    if ($skip) { Info "-> uebersprungen: $skip" }
    else {
        Ok "-> wird eingespielt"
        $order = switch ($target) { 'db' { if ($what -match 'Windows UEFI CA 2023') { 1 } else { 2 } } 'KEK' { 3 } 'dbx' { 4 } }
        $item = [pscustomobject]@{ Order = $order; Target = $target; What = $what; Payloads = @($p) }
        $plan += $item
        if ($target -ne 'dbx') { $planned[$certKey] = $item }
    }
}
$plan = @($plan | Sort-Object Order)
# Praxis: DBUpdate1P2023.bin wurde von mehreren Firmwares abgelehnt, dbupdate2024.bin angenommen -> 1P-Dateien zuletzt probieren
foreach ($s in $plan) { $s.Payloads = @($s.Payloads | Sort-Object { if ($_.Name -match '1P') { 1 } else { 0 } }) }

if ($plan.Count -eq 0) {
    Section "Ergebnis"
    Ok "Nichts zu tun - alle gefundenen Zertifikate sind bereits eingetragen (oder keine passenden Dateien)."
    Finish
}

Section "Plan"
$i = 0; foreach ($s in $plan) { $i++; Info ("{0}. {1,-4} <- {2}  [{3}]" -f $i, $s.Target, $s.What, (($s.Payloads | ForEach-Object { $_.Name }) -join ' / ')) }

if (-not $Execute) {
    Write-Host ""
    Warn "TROCKENLAUF - nichts geschrieben. Zum Ausfuehren mit -Execute starten (4_Manuell_einspielen.cmd)."
    Finish
}

# ================================================================ Ausfuehren
Section "WARNUNG"
Bad "Microsoft hat das automatische Update fuer dieses Geraet evtl. wegen eines Firmwarefehlers gesperrt."
Bad ("Wenn der PC danach nicht startet: Firmware-Setup ({0}, Taste {1}) -> Secure Boot AUSSCHALTEN." -f $vi.Vendor, $vi.Key)
Bad ("  Schluessel-Reset ({0}) NUR, solange der Boot-Manager noch 2011-signiert ist." -f $vi.Reset)
if ($vi.Extra) { Bad ("  {0}" -f $vi.Extra) }
Info "Sicherung liegt in: $backupDir"

try {
    $blv = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($blv.ProtectionStatus -eq 'On') {
        Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 3 -ErrorAction Stop | Out-Null
        Ok "BitLocker fuer 3 Neustarts angehalten"
    }
} catch {}

$tmp = Join-Path $env:TEMP "sbmanual_$stamp"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$okCount = 0

foreach ($s in $plan) {
    Write-Host ""
    $answer = Read-Host ("'{0}' in {1} eintragen? Zum Bestaetigen JA tippen" -f $s.What, $s.Target)
    if ($answer -cne 'JA') { Info "uebersprungen"; continue }

    $n = 0
    foreach ($pl in $s.Payloads) {
        $n++
        if ($n -gt 1) { Info ("Probiere Ersatzdatei {0} ..." -f $pl.Name) }
        $cFile = Join-Path $tmp ($pl.Name + '.content')
        $sFile = Join-Path $tmp ($pl.Name + '.p7')
        [IO.File]::WriteAllBytes($cFile, $pl.Content)
        [IO.File]::WriteAllBytes($sFile, $pl.Sig)

        $before = (Get-SecureBootUEFI -Name $s.Target).Bytes.Length
        try {
            Set-SecureBootUEFI -Name $s.Target -Time $pl.Time -ContentFilePath $cFile -SignedFilePath $sFile -AppendWrite -ErrorAction Stop | Out-Null
            $after = (Get-SecureBootUEFI -Name $s.Target).Bytes.Length
            if ($after -gt $before -or $s.Target -eq 'dbx') {
                Ok ("{0} geschrieben aus {1} ({2} -> {3} Bytes)" -f $s.Target, $pl.Name, $before, $after); $okCount++; break
            }
            Warn ("{0}: Befehl ohne Fehler, aber {1} unveraendert ({2} Bytes)" -f $pl.Name, $s.Target, $after)
        } catch {
            Bad ("{0}: Firmware hat abgelehnt: {1}" -f $pl.Name, $_.Exception.Message)
            if ($s.Target -eq 'dbx') { Info "(dbx: manche Firmwares lehnen Anhaengen ab, wenn die vorhandene dbx einen neueren Zeitstempel hat - z.B. vom Hersteller vorbelegt. Mit Microsoft-Dateien nicht loesbar.)" }
            if ($s.Target -eq 'KEK') { Info "(erwartet, wenn die KEK-Datei nicht mit dem PK dieses Geraets signiert ist)" }
        }
    }
}
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue

# ================================================================ Kontrolle
Section "Kontrolle"
$db  = Get-VarEsl 'db'; $kek = Get-VarEsl 'KEK'
foreach ($n in 'Windows UEFI CA 2023','Microsoft UEFI CA 2023','Option ROM UEFI CA 2023') {
    if ($db.Certs | Where-Object { $_.Subject -match $n }) { Ok "db:  $n" } else { Bad "db:  $n fehlt" }
}
if ($kek.Certs | Where-Object { $_.Subject -match 'KEK 2K CA 2023' }) { Ok "KEK: Microsoft Corporation KEK 2K CA 2023" } else { Bad "KEK: KEK 2K CA 2023 fehlt" }

if ($okCount -gt 0) {
    Write-Host ""
    Warn "Jetzt NEU STARTEN und pruefen, ob der PC normal bootet."
    Info ("Notfall: Firmware-Setup ({0}, Taste {1}) -> Secure Boot AUSSCHALTEN, booten, Protokoll pruefen." -f $vi.Vendor, $vi.Key)
    Info "Danach SecureBootCheck.ps1 (1_Pruefen.cmd) laufen lassen."
    Info "Ist 'Windows UEFI CA 2023' in der db, kann Windows den neuen Boot-Manager installieren"
    Info "(2_Update_anstossen.cmd) - sofern die Microsoft-Sperre das nicht ebenfalls blockiert."
}
Finish
