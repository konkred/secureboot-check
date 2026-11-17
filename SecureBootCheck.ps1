<#
.SYNOPSIS
    Secure-Boot-Zertifikate (2011 -> 2023) pruefen und Update anstossen.

.DESCRIPTION
    Ohne Parameter: reine Diagnose, aendert NICHTS.
      - Geraet, BIOS, Windows-Build
      - Secure-Boot-Status, PK / KEK / db / dbx (echte Zertifikate inkl. Ablaufdatum)
      - Erkennung von Test-PKs ("DO NOT TRUST" / PKfail)
      - Signatur des Boot-Managers auf der EFI-Partition (2011 oder 2023)
      - Registry-Status des Microsoft-Servicing
      - TPM-WMI-Ereignisse (1795/1796/1801/1803/1808 ...)
      - BitLocker-Status
      - Bewertung + naechster Schritt

    Mit -Apply: BitLocker anhalten (3 Neustarts), AvailableUpdates = 0x5944 setzen,
    geplanten Task "Secure-Boot-Update" starten, Ergebnis auswerten.
    Danach neu starten und das Skript erneut ausfuehren (ggf. mehrmals).

    Ein Protokoll wird neben dem Skript abgelegt: SecureBoot_<PC>_<Datum>.txt

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\SecureBootCheck.ps1
    powershell -ExecutionPolicy Bypass -File .\SecureBootCheck.ps1 -Apply
#>
[CmdletBinding()]
param(
    [switch]$Apply,     # Update anstossen
    [switch]$Force,     # AvailableUpdates auch setzen, wenn bereits ein Wert ansteht
    [switch]$NoPause    # am Ende nicht auf Enter warten
)
$ScriptVersion = '1.3'

# ---------------------------------------------------------------- Admin / Elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($Apply)   { $argList += '-Apply' }
    if ($Force)   { $argList += '-Force' }
    if ($NoPause) { $argList += '-NoPause' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

$ErrorActionPreference = 'Continue'
$scriptDir = Split-Path -Parent $PSCommandPath

# Protokoll zuerst LOKAL schreiben (ueberlebt abgezogenen Stick), am Ende in den Skriptordner kopieren
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
$logFile   = Join-Path (Get-SubDir $localDir 'Logs') ("{0}_{1}_{2}.txt" -f 'SecureBoot', $deviceId, (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'))
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
        $v.Vendor = 'HP'; $v.Key = 'F10'; $v.Reset = 'Advanced (aeltere Modelle: Security) -> Secure Boot Configuration -> Secure-Boot-Schluessel auf Werkseinstellung zuruecksetzen'; $v.Extra = 'Falls vorhanden: "Key Ownership" zeigt, ob HP- oder eigene Schluessel gelten (wichtig fuer 6_). "Sure Start Secure Boot Keys Protection" deaktivieren.'
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

# ---------------------------------------------------------------- Helfer
$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$Level, [string]$Text) { $findings.Add([pscustomobject]@{Level=$Level; Text=$Text}) }
function Section([string]$t) { Write-Host ""; Write-Host ("=" * 70) -ForegroundColor DarkCyan; Write-Host " $t" -ForegroundColor Cyan; Write-Host ("=" * 70) -ForegroundColor DarkCyan }
function Ok([string]$t)   { Write-Host "  [OK]   $t" -ForegroundColor Green }
function Bad([string]$t)  { Write-Host "  [!!]   $t" -ForegroundColor Red }
function Warn([string]$t) { Write-Host "  [??]   $t" -ForegroundColor Yellow }
function Info([string]$t) { Write-Host "         $t" }

$X509Guid   = [Guid]'a5c059a1-94e4-4aa7-87b5-ab155c2bf072'
$Sha256Guid = [Guid]'c1c41626-504c-4092-aca9-41f936934328'

function Get-EfiSignatureList([string]$Name) {
    # Parst EFI_SIGNATURE_LIST-Strukturen einer Secure-Boot-Variable
    try { $var = Get-SecureBootUEFI -Name $Name -ErrorAction Stop } catch { return $null }
    $b = $var.Bytes
    $certs = @(); $hashCount = 0; $otherCount = 0
    if (-not $b) { return [pscustomobject]@{Certs=@(); Hashes=0; Other=0; Valid=$true; Bytes=0} }
    $o = 0
    while ($o + 28 -le $b.Length) {
        $type     = New-Object Guid (,[byte[]]$b[$o..($o + 15)])
        $listSize = [BitConverter]::ToUInt32($b, $o + 16)
        $hdrSize  = [BitConverter]::ToUInt32($b, $o + 20)
        $sigSize  = [BitConverter]::ToUInt32($b, $o + 24)
        if ($listSize -lt 28 -or $sigSize -lt 16 -or ($o + $listSize) -gt $b.Length) { break }
        $p   = $o + 28 + $hdrSize
        $end = $o + $listSize
        while ($p + $sigSize -le $end) {
            if ($type -eq $X509Guid) {
                $data = [byte[]]$b[($p + 16)..($p + $sigSize - 1)]
                try {
                    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$data)
                    $certs += $c
                } catch { $otherCount++ }
            } elseif ($type -eq $Sha256Guid) { $hashCount++ }
            else { $otherCount++ }
            $p += $sigSize
        }
        $o += $listSize
    }
    # Valid = die Variable besteht vollstaendig aus sauberen Signaturlisten (kein unlesbarer Rest)
    [pscustomobject]@{ Certs = $certs; Hashes = $hashCount; Other = $otherCount; Valid = ($o -eq $b.Length); Bytes = $b.Length; GoodBytes = $o }
}

function Get-PeEmbeddedCerts([string]$Path) {
    # Liest ALLE Zertifikate aus den eingebetteten Authenticode-Signaturen (inkl. verschachtelter Signaturen)
    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
    $out = @()
    try {
        $b = [IO.File]::ReadAllBytes($Path)
        $pe = [BitConverter]::ToInt32($b, 0x3C)
        $opt = $pe + 24
        $magic = [BitConverter]::ToUInt16($b, $opt)
        $dd = if ($magic -eq 0x20b) { $opt + 112 } else { $opt + 96 }
        $secOff  = [BitConverter]::ToInt32($b, $dd + 4 * 8)
        $secSize = [BitConverter]::ToInt32($b, $dd + 4 * 8 + 4)
        if ($secOff -le 0 -or $secSize -le 8) { return @() }
        $p = $secOff; $end = $secOff + $secSize
        $queue = New-Object System.Collections.Generic.Queue[byte[]]
        while ($p + 8 -le $end) {
            $len = [BitConverter]::ToInt32($b, $p)
            if ($len -le 8) { break }
            $queue.Enqueue([byte[]]$b[($p + 8)..($p + $len - 1)])
            $p += [int]([Math]::Ceiling($len / 8.0) * 8)
        }
        while ($queue.Count -gt 0) {
            $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
            $cms.Decode($queue.Dequeue())
            foreach ($c in $cms.Certificates) { if (-not ($out | Where-Object { $_.Thumbprint -eq $c.Thumbprint })) { $out += $c } }
            foreach ($si in $cms.SignerInfos) {
                foreach ($a in $si.UnsignedAttributes) {
                    if ($a.Oid.Value -eq '1.3.6.1.4.1.311.2.4.1') { foreach ($v in $a.Values) { $queue.Enqueue($v.RawData) } }
                }
            }
        }
    } catch { Warn "Signatur konnte nicht geparst werden: $_" }
    return $out
}

function Get-CN([string]$dn) { if ($dn -match 'CN=([^,]+)') { $Matches[1].Trim() } else { $dn } }

function Show-Certs($list, [string]$label) {
    if ($null -eq $list) { Bad "$label konnte nicht gelesen werden"; return }
    if ($list.Certs.Count -eq 0) { Warn "$label enthaelt keine X.509-Zertifikate" }
    foreach ($c in $list.Certs) {
        $cn  = Get-CN $c.Subject
        $exp = $c.NotAfter.ToString('yyyy-MM-dd')
        $txt = "{0,-45} gueltig bis {1}" -f $cn, $exp
        if ($c.NotAfter -lt (Get-Date)) { Warn "$txt  (abgelaufen)" } else { Ok $txt }
    }
    if ($list.Hashes -gt 0) { Info ("+ {0} SHA256-Hashes" -f $list.Hashes) }
    if ($list.Other  -gt 0) { Info ("+ {0} sonstige Eintraege" -f $list.Other) }
}

function Has-Cert($list, [string]$pattern) {
    if ($null -eq $list) { return $false }
    return [bool]($list.Certs | Where-Object { $_.Subject -match $pattern })
}

function Test-VarIntegrity($list, [string]$label) {
    # Meldet Variablen, die hinter den gueltigen Signaturlisten unlesbare Daten enthalten
    if ($null -eq $list -or $list.Valid) { return }
    Bad ("{0} ist BESCHAEDIGT: nur {1} von {2} Bytes sind gueltige Signaturlisten, der Rest ist unlesbar." -f $label, $list.GoodBytes, $list.Bytes)
    if ($label -eq 'dbx') {
        Add-Finding 'Bad' ("Die Sperrliste (dbx) ist BESCHAEDIGT. Mit aktivem Secure Boot startet der PC dann oft nur mit 'invalid signature'. Rettung: Secure Boot aus (Taste {0}), Windows starten, 6_Schluessel_neu_aufbauen.cmd ausfuehren (baut die dbx sauber neu auf) oder mit 7_Sicherung_zurueckspielen.cmd eine aeltere Sicherung zurueckschreiben." -f $vi.Key)
    } else {
        Add-Finding 'Bad' ("{0} ist BESCHAEDIGT. Rettung: Secure Boot aus (Taste {1}), Windows starten und mit 7_Sicherung_zurueckspielen.cmd eine Sicherung von vorher zurueckschreiben." -f $label, $vi.Key)
    }
}

$EventInfo = @{
    1795 = 'Firmware hat beim Schreiben einer Secure-Boot-Variable einen Fehler gemeldet'
    1796 = 'Unerwarteter Fehler beim Secure-Boot-Update'
    1799 = 'Boot-Manager mit 2023-Signatur wurde installiert'
    1800 = 'Neustart erforderlich, um das Update fortzusetzen'
    1797 = 'Boot-Manager-Update abgebrochen: Windows UEFI CA 2023 fehlt in der db'
    1801 = 'Zertifikate aktualisiert, aber noch nicht vollstaendig angewendet'
    1802 = 'Von Microsoft BLOCKIERT wegen bekanntem Firmwarefehler dieses Modells'
    1803 = 'KEIN vom Hersteller (PK) signiertes KEK-Update fuer dieses Geraet gefunden'
    1808 = 'Alle Secure-Boot-Zertifikate erfolgreich aktualisiert'
}

$AvailableBits = [ordered]@{
    0x0004 = 'KEK 2023 eintragen (braucht PK-signierte Datei vom Hersteller)'
    0x0040 = 'Windows UEFI CA 2023 in db eintragen'
    0x0100 = 'Boot-Manager mit 2023-Signatur installieren'
    0x0800 = 'Microsoft (Option ROM) UEFI CA 2023 in db eintragen'
    0x1000 = 'Microsoft UEFI CA 2023 in db eintragen'
    0x4000 = 'Bedingung: Dritthersteller-CAs nur, wenn 2011er UEFI CA vorhanden'
}
function Show-AvailableUpdates([int]$v) {
    if ($v -eq 0) { Ok "AvailableUpdates = 0x0 (nichts ausstehend)"; return }
    Warn ("AvailableUpdates = 0x{0:X} (noch ausstehend:)" -f $v)
    # GetEnumerator statt $AvailableBits[$k]: ein int-Index auf [ordered] waere ein Positionsindex
    foreach ($e in $AvailableBits.GetEnumerator()) { if ($v -band $e.Key) { Info ("  0x{0:X4}  {1}" -f $e.Key, $e.Value) } }
}

$sbKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot'
$svcKey = "$sbKey\Servicing"
function Get-AvailableUpdates { try { [int](Get-ItemProperty -Path $sbKey -Name AvailableUpdates -ErrorAction Stop).AvailableUpdates } catch { 0 } }

function Get-TpmWmiEvents([datetime]$Since) {
    try {
        Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-TPM-WMI'; StartTime=$Since } -ErrorAction Stop |
            Where-Object { $_.Id -ge 1795 -and $_.Id -le 1810 }   # nur Secure-Boot-Servicing, kein TPM-Attestierungs-Rauschen
    } catch { @() }
}

# ================================================================ 1. System
Section "1. System"
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$cv   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Info ("Skript:    Version {0}" -f $ScriptVersion)
Info ("PC:        {0}" -f $env:COMPUTERNAME)
Info ("Seriennr.: {0}" -f $(if ($serial) { "$serial  (Ordner: $deviceId)" } else { "nicht auslesbar (Ordner: Hostname)" }))
Info ("Modell:    {0} {1}" -f $cs.Manufacturer, $cs.Model)
$biosDate = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString("yyyy-MM-dd") } else { "?" }
Info ("BIOS:      {0}  ({1})" -f $bios.SMBIOSBIOSVersion, $biosDate)
Info ("Windows:   {0} {1}  Build {2}.{3}" -f $cv.ProductName, $cv.DisplayVersion, $cv.CurrentBuildNumber, $cv.UBR)
if ([int]$cv.CurrentBuildNumber -ge 22000 -and $cv.ProductName -match 'Windows 10') { Info "           (ProductName sagt Windows 10, Build >= 22000 = tatsaechlich Windows 11)" }
Info ("Firmware-Setup ({0}): Taste {1}" -f $vi.Vendor, $vi.Key)
Info ("Schluessel-Reset:   {0}" -f $vi.Reset)
Info  "                    (Vorsicht nach dem Boot-Manager-Tausch - siehe Ergebnis)"
if ($vi.Extra) { Info ("                    {0}" -f $vi.Extra) }

$task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update' -ErrorAction SilentlyContinue
if ($task) { Ok "Geplanter Task 'Secure-Boot-Update' vorhanden" }
else { Bad "Geplanter Task 'Secure-Boot-Update' fehlt -> Windows-Updates installieren"; Add-Finding 'Bad' 'Windows ist zu alt (Task fehlt). Erst alle Windows-Updates installieren.' }

# ================================================================ 2. Secure Boot
Section "2. Secure-Boot-Status"
$sbOn = $null
try { $sbOn = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sbOn = $null }
$setup = $null
if ($null -ne $sbOn) { try { $setup = (Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop).Bytes[0] } catch {} }
$pkPresent = $false
if ($null -ne $sbOn) { try { $pkPresent = [bool](Get-SecureBootUEFI -Name PK -ErrorAction Stop).Bytes } catch {} }
$otherKeys = $false
if ($null -ne $sbOn) { foreach ($n in 'KEK','db') { try { if ((Get-SecureBootUEFI -Name $n -ErrorAction Stop).Bytes) { $otherKeys = $true } } catch {} } }
# Geraet ohne jegliche Schluessel und ohne Secure Boot (z.B. Thin Clients): von den Zertifikaten nicht betroffen.
# Setup Mode MIT KEK/db, aber ohne PK ist dagegen ein halb fertiger Neuaufbau (z.B. HP mit "Custom Keys").
$noKeys = ($sbOn -eq $false -and $setup -eq 1 -and -not $pkPresent -and -not $otherKeys)
$pkMissing = ($setup -eq 1 -and -not $pkPresent -and $otherKeys)

if ($sbOn -eq $true)      { Ok "Secure Boot ist AKTIV" }
elseif ($noKeys) {
    Info "Secure Boot ist AUS und es sind KEINE Schluessel hinterlegt (UEFI, Setup Mode)."
    Info "Dieses Geraet nutzt Secure Boot nicht."
    Add-Finding 'Ok' 'NICHT BETROFFEN: ohne Secure Boot prueft die Firmware keine Signaturen, abgelaufene Zertifikate spielen keine Rolle. Nichts zu tun. (Nur falls das Firmware-Setup doch eine Secure-Boot-Option bietet: dort Standard-Schluessel laden, Secure Boot an, dann erneut pruefen.)'
}
elseif ($sbOn -eq $false) { Bad "Secure Boot ist AUS (UEFI vorhanden)"; if (-not $pkMissing) { Add-Finding 'Bad' 'Secure Boot im Firmware-Setup aktivieren (Legacy/CSM aus).' } }
else                      { Bad "Kein UEFI / Legacy-Boot - Secure Boot nicht moeglich"; Add-Finding 'Warn' 'System bootet im Legacy-Modus und nutzt kein Secure Boot - von den Zertifikaten nicht betroffen. Fuer Secure Boot: auf UEFI umstellen (MBR2GPT) und Secure Boot aktivieren.' }

if ($null -ne $sbOn -and -not $noKeys) {
    if ($pkMissing) {
        Bad "Firmware ist im SETUP MODE: KEK und db sind vorhanden, aber KEIN PK"
        Add-Finding 'Bad' ("Setup Mode ohne PK: KEK und db sind da, der PK fehlt. So laesst sich Secure Boot nicht einschalten. Typisch, wenn die Firmware beim Neuaufbau (6_) den Original-PK abgelehnt hat, z.B. HP mit Key Ownership 'Custom Keys'. Zurueck zum sicheren Stand: Firmware-Setup (Taste {0}), Secure Boot AUS, Werksschluessel laden (HP: Key Ownership 'HP Keys'), Windows starten, 5_Manuell_mit_dbx.cmd, dann Secure Boot wieder AN." -f $vi.Key)
    }
    elseif ($setup -eq 1) { Warn "Firmware ist im SETUP MODE (keine Schluessel / PK geloescht)"; Add-Finding 'Warn' 'Firmware im Setup Mode: Schluessel fehlen. Im Firmware-Setup Standard-Schluessel laden bzw. Phase 2 von 6_Schluessel_neu_aufbauen.cmd ausfuehren.' }
    elseif ($setup -eq 0) { Ok "User Mode (Schluessel geladen)" }
}

# ================================================================ 3. Schluessel
$pk = $kek = $db = $dbx = $null
if ($null -ne $sbOn -and -not $noKeys) {
    Section "3. Platform Key (PK)"
    $pk = Get-EfiSignatureList 'PK'
    Show-Certs $pk 'PK'
    Test-VarIntegrity $pk 'PK'
    if ($pk -and ($pk.Certs | Where-Object { $_.Subject -match 'DO NOT TRUST|DO NOT SHIP' })) {
        Bad "PK ist ein AMI-TESTSCHLUESSEL (PKfail) - Secure Boot ist praktisch wirkungslos!"
        Add-Finding 'Bad' ("Test-PK (PKfail) erkannt: BIOS-/Firmware-Update von {0} noetig oder eigene Schluessel einspielen." -f $vi.Vendor)
    }
    if ($pk -and $pk.Certs.Count -gt 0) { Info ("Aussteller: {0}" -f (Get-CN $pk.Certs[0].Issuer)) }

    Section "4. Key Exchange Key (KEK)"
    $kek = Get-EfiSignatureList 'KEK'
    Show-Certs $kek 'KEK'
    Test-VarIntegrity $kek 'KEK'

    Section "5. Erlaubte Signaturen (db)"
    $db = Get-EfiSignatureList 'db'
    Show-Certs $db 'db'
    Test-VarIntegrity $db 'db'

    Section "5b. Werkseinstellungen der Firmware (dbDefault)"
    $dbDef = Get-EfiSignatureList 'dbDefault'
    $defHasWinCA2023 = $null
    if ($null -eq $dbDef) { Info "dbDefault nicht lesbar (Firmware stellt es nicht bereit)" }
    else {
        $defHasWinCA2023 = Has-Cert $dbDef 'Windows UEFI CA 2023'
        if ($dbDef.Certs.Count -eq 0) { Info "dbDefault ist leer"; $defHasWinCA2023 = $null }
        elseif ($defHasWinCA2023) { Ok "Werkseinstellungen enthalten die Windows UEFI CA 2023 (Schluessel-Reset ist ungefaehrlich)" }
        else { Warn "Werkseinstellungen enthalten KEINE Windows UEFI CA 2023" }
    }

    Section "6. Sperrliste (dbx)"
    $dbx = Get-EfiSignatureList 'dbx'
    if ($dbx) {
        Info ("{0} Hash-Eintraege, {1} Zertifikate" -f $dbx.Hashes, $dbx.Certs.Count)
        if ($dbx.Other -gt 0) { Info ("{0} Eintraege anderen Typs" -f $dbx.Other) }
        Test-VarIntegrity $dbx 'dbx'
        if ($dbx.Valid) { Ok "Sperrliste ist formal in Ordnung" }
        if ($dbx.Hashes -lt 50 -and $dbx.Certs.Count -eq 0) {
            Warn "Sperrliste ist praktisch LEER - es wurden nie DBX-Updates eingespielt"
            Add-Finding 'Warn' 'dbx ist (fast) leer: bekannte unsichere Bootloader (z.B. BlackLotus-Luecke) sind nicht gesperrt. Abhilfe: 5_Manuell_mit_dbx.cmd; lehnt die Firmware das ab, 8_dbx_schrittweise.cmd.'
        }
        foreach ($c in $dbx.Certs) { Info ("  gesperrt: {0}" -f (Get-CN $c.Subject)) }
        if ($dbx.Certs | Where-Object { $_.Subject -match 'Windows Production PCA 2011' }) {
            Info "  -> 2011er Windows-CA ist gesperrt (Revocation bereits angewendet)"
        }
    } else { Warn "dbx nicht lesbar" }
}

$hasKek2023   = Has-Cert $kek 'KEK 2K CA 2023'
$hasWinCA2023 = Has-Cert $db  'Windows UEFI CA 2023'
$hasUefiCA2023= Has-Cert $db  'Microsoft UEFI CA 2023'
$hasOromCA2023= Has-Cert $db  'Option ROM UEFI CA 2023'

function Test-BootMgr {
    # $true = 2023, $false = 2011, $null = unklar
    $result = $null
    $letter = (68..90 | ForEach-Object { [char]$_ } | Where-Object { -not (Test-Path "$($_):\") } | Select-Object -Last 1)
    if ($letter) {
        $mp = "$($letter):"
        try {
            mountvol $mp /S 2>$null | Out-Null
            $bm = "$mp\EFI\Microsoft\Boot\bootmgfw.efi"
            if (Test-Path $bm) {
                $embedded = @(Get-PeEmbeddedCerts $bm)
                if ($embedded.Count -eq 0) { Warn "Keine eingebettete Signatur lesbar" }
                else {
                    Info "Eingebettete Zertifikate in bootmgfw.efi:"
                    foreach ($c in $embedded) { Info ("  {0,-50} <- {1}" -f (Get-CN $c.Subject), (Get-CN $c.Issuer)) }
                }
                $names = ($embedded | ForEach-Object { $_.Subject; $_.Issuer }) -join '|'
                if ($names -match 'Windows UEFI CA 2023')               { Ok "Boot-Manager kettet zur Windows UEFI CA 2023"; $result = $true }
                elseif ($names -match 'Windows Production PCA 2011')    { Warn "Boot-Manager kettet noch zur Windows Production PCA 2011"; $result = $false }
                else { Warn "Zertifikatskette nicht eindeutig zuzuordnen (siehe oben)" }
            } else { Warn "bootmgfw.efi nicht gefunden" }
        } catch { Warn "EFI-Partition konnte nicht gelesen werden: $_" }
        finally { mountvol $mp /D 2>$null | Out-Null }
    } else { Info "uebersprungen" }
    return $result
}

function Get-ChainKind($certs) {
    # Ordnet die eingebetteten Zertifikate einer EFI-Datei grob ein
    $certs = @($certs)
    if ($certs.Count -eq 0) { return 'keine Signatur lesbar' }
    $names = ($certs | ForEach-Object { $_.Subject; $_.Issuer }) -join '|'
    if ($names -match 'Windows UEFI CA 2023')        { return 'Windows, 2023 (Windows UEFI CA 2023)' }
    if ($names -match 'Windows Production PCA 2011') { return 'Windows, 2011 (Windows Production PCA 2011)' }
    if ($names -match 'Microsoft UEFI CA 2023')      { return 'Fremd-Bootloader, Microsoft UEFI CA 2023' }
    if ($names -match 'Microsoft Corporation UEFI CA 2011') { return 'Fremd-Bootloader, Microsoft UEFI CA 2011 (z.B. Linux-shim)' }
    'unbekannt, ausgestellt von ' + (Get-CN $certs[-1].Issuer)
}

function Show-BootPaths {
    # Ausweich-Bootloader \EFI\Boot\bootx64.efi, Ordner auf der EFI-Partition, Booteintraege der Firmware
    $kind = $null
    $letter = (68..90 | ForEach-Object { [char]$_ } | Where-Object { -not (Test-Path "$($_):\") } | Select-Object -Last 1)
    if ($letter) {
        $mp = "$($letter):"
        try {
            mountvol $mp /S 2>$null | Out-Null
            $dirs = @(Get-ChildItem "$mp\EFI" -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
            if ($dirs.Count) { Info ("Ordner unter \EFI: {0}" -f ($dirs -join ', ')) }
            $fb = "$mp\EFI\Boot\bootx64.efi"
            if (Test-Path $fb) {
                $kind = Get-ChainKind (Get-PeEmbeddedCerts $fb)
                $txt = "Ausweich-Bootloader \EFI\Boot\bootx64.efi: $kind"
                if ($kind -match '^Windows, 2011' -and $bootmgr2023 -eq $true) { Warn $txt } else { Info $txt }
            } else { Info "Kein Ausweich-Bootloader \EFI\Boot\bootx64.efi vorhanden" }
        } catch { Warn "EFI-Partition konnte nicht gelesen werden: $_" }
        finally { mountvol $mp /D 2>$null | Out-Null }
    }
    try {
        $out = @(& bcdedit.exe /enum firmware 2>$null)
        $entries = @(); $desc = $null; $path = $null
        foreach ($line in ($out + '')) {
            if ($line -match '^\s*$') {
                if ($desc) { $entries += [pscustomobject]@{ Desc = $desc; Path = $path } }
                $desc = $null; $path = $null; continue
            }
            if ($line -match '^\s*(description|Beschreibung)\s+(.+)$') { $desc = $Matches[2].Trim() }
            elseif ($line -match '^\s*(path|Pfad)\s+(.+)$')        { $path = $Matches[2].Trim() }
        }
        $entries = @($entries | Where-Object { $_.Path })
        if ($entries.Count) {
            Info "Booteintraege der Firmware (laut bcdedit /enum firmware):"
            foreach ($e in $entries) { Info ("  {0,-30} {1}" -f $e.Desc, $e.Path) }
        } else { Info "Booteintraege der Firmware nicht auslesbar" }
    } catch { Info "Booteintraege der Firmware nicht auslesbar" }
    $kind
}

# ================================================================ 7. Boot-Manager
Section "7. Boot-Manager auf der EFI-Partition"
$bootmgr2023 = $null
$fallbackKind = $null
if ($null -ne $sbOn -and -not $noKeys) {
    $bootmgr2023 = Test-BootMgr
    Write-Host ""
    $fallbackKind = Show-BootPaths
    if ($fallbackKind -match '^Windows, 2011' -and $bootmgr2023 -eq $true) {
        Add-Finding 'Warn' 'Der Ausweich-Bootloader \EFI\Boot\bootx64.efi ist noch mit der PCA 2011 signiert. Solange die Firmware den Windows-Boot-Manager direkt startet, spielt das keine Rolle. Startet sie den Ausweichpfad (z.B. nach Verlust der Booteintraege), braucht sie weiterhin die PCA 2011 in der db.'
    }
} else { Info "uebersprungen" }

# ================================================================ 8. Registry
Section "8. Windows-Servicing (Registry)"
$avail = Get-AvailableUpdates
Show-AvailableUpdates $avail
if (Test-Path $svcKey) {
    $svc = Get-ItemProperty $svcKey
    $svc.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { Info ("{0,-30} = {1}" -f $_.Name, $_.Value) }
} else { Info "Kein Servicing-Schluessel vorhanden (Update noch nie gelaufen)" }

# ================================================================ 9. BitLocker
Section "9. BitLocker"
$blv = $null
try { $blv = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop } catch {}
if ($blv) {
    Info ("Status: {0}, Schutz: {1}" -f $blv.VolumeStatus, $blv.ProtectionStatus)
    if ($blv.ProtectionStatus -eq 'On') { Warn "BitLocker aktiv -> vor dem Update anhalten (macht -Apply automatisch)" }
} else { Info "BitLocker nicht verfuegbar / nicht aktiv" }

# ================================================================ 10. Ereignisse
Section "10. TPM-WMI-Ereignisse (letzte 60 Tage)"
$events = @(Get-TpmWmiEvents (Get-Date).AddDays(-60))
if ($events.Count -eq 0) { Info "Keine relevanten Ereignisse gefunden" }
else {
    foreach ($e in ($events | Select-Object -First 15)) {
        $desc = if ($EventInfo.ContainsKey($e.Id)) { $EventInfo[$e.Id] } else { ($e.Message -split "`r?`n")[0] }
        $line = "{0}  ID {1}: {2}" -f $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $e.Id, $desc
        switch ($e.Id) { 1808 { Ok $line } { $_ -in 1795,1796,1797,1802,1803 } { Bad $line } default { Info $line } }
    }
    if ($events.Count -gt 15) { Info ("... {0} weitere" -f ($events.Count - 15)) }
}
# IDs des letzten Durchlaufs (alle Ereignisse innerhalb 2 Minuten vor dem neuesten)
function Get-RecentIds($evs) {
    if (-not $evs -or $evs.Count -eq 0) { return @() }
    $newest = $evs[0].TimeCreated
    @($evs | Where-Object { $_.TimeCreated -ge $newest.AddMinutes(-2) } | ForEach-Object { $_.Id } | Select-Object -Unique)
}
$recentIds = Get-RecentIds $events

# Bekannter Firmwarefehler laut Microsoft-Servicing?
$firmwareKI = $null
if (Test-Path $svcKey) {
    $firmwareKI = (Get-ItemProperty $svcKey).PSObject.Properties |
        Where-Object { $_.Name -like '*ErrorReason' -and "$($_.Value)" -like 'Firmware_KI*' } |
        Select-Object -First 1 -ExpandProperty Value
}

# ================================================================ 11. Apply
if ($Apply) {
    Section "11. Update anstossen"
    if ($sbOn -ne $true) {
        Bad "Abbruch: Secure Boot ist nicht aktiv."
    } elseif (-not $task) {
        Bad "Abbruch: Task 'Secure-Boot-Update' fehlt."
    } else {
        if ($blv -and $blv.ProtectionStatus -eq 'On') {
            try { Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 3 -ErrorAction Stop | Out-Null; Ok "BitLocker fuer 3 Neustarts angehalten" }
            catch { Bad "BitLocker konnte nicht angehalten werden: $_ - Abbruch."; $task = $null }
        }
        if ($task) {
            if ($avail -ne 0 -and -not $Force) {
                Info ("AvailableUpdates steht bereits auf 0x{0:X} - wird nicht ueberschrieben (sonst -Force)" -f $avail)
            } else {
                Set-ItemProperty -Path $sbKey -Name AvailableUpdates -Value 0x5944 -Type DWord
                Ok "AvailableUpdates = 0x5944 gesetzt"
            }
            $start = Get-Date
            Start-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update'
            Info "Task gestartet, warte auf Abschluss ..."
            $t = 0
            do { Start-Sleep -Seconds 3; $t += 3; $state = (Get-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update').State }
            while ($state -eq 'Running' -and $t -lt 180)
            Start-Sleep -Seconds 5
            $result = (Get-ScheduledTaskInfo -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update').LastTaskResult
            Info ("Task beendet (Ergebnis 0x{0:X})" -f $result)

            $avail = Get-AvailableUpdates
            Show-AvailableUpdates $avail

            $newEvents = @(Get-TpmWmiEvents $start)
            if ($newEvents.Count -eq 0) { Info "Keine neuen Ereignisse (oft erst nach Neustart)" }
            foreach ($e in $newEvents) {
                $desc = if ($EventInfo.ContainsKey($e.Id)) { $EventInfo[$e.Id] } else { ($e.Message -split "`r?`n")[0] }
                Info ("NEU  ID {0}: {1}" -f $e.Id, $desc)
            }
            if ($newEvents.Count -gt 0) { $recentIds = Get-RecentIds $newEvents }

            # Neu einlesen
            $kek = Get-EfiSignatureList 'KEK'; $db = Get-EfiSignatureList 'db'
            $hasKek2023   = Has-Cert $kek 'KEK 2K CA 2023'
            $hasWinCA2023 = Has-Cert $db  'Windows UEFI CA 2023'
            $hasUefiCA2023= Has-Cert $db  'Microsoft UEFI CA 2023'
            $hasOromCA2023= Has-Cert $db  'Option ROM UEFI CA 2023'
            Info "Boot-Manager erneut pruefen:"
            $bootmgr2023 = Test-BootMgr
        }
    }
}

# ================================================================ Bewertung
Section "ERGEBNIS fuer $env:COMPUTERNAME ($($cs.Model))"
function Flag([bool]$v, [string]$t) { if ($v) { Ok $t } else { Bad $t } }
if ($null -ne $sbOn -and -not $noKeys) {
    Flag $hasKek2023    "KEK:  Microsoft Corporation KEK 2K CA 2023"
    Flag $hasWinCA2023  "db:   Windows UEFI CA 2023"
    Flag $hasUefiCA2023 "db:   Microsoft UEFI CA 2023"
    Flag $hasOromCA2023 "db:   Microsoft Option ROM UEFI CA 2023"
    if ($null -ne $bootmgr2023) { Flag $bootmgr2023 "Boot-Manager mit 2023 signiert" }
}

# Schluessel-Reset waere nach dem Boot-Manager-Tausch gefaehrlich
if ($bootmgr2023 -eq $true -and $defHasWinCA2023 -ne $true) {
    Add-Finding 'Bad' ("KEIN Schluessel-Reset im Firmware-Setup mehr! Die Werkseinstellungen enthalten die Windows UEFI CA 2023 nicht, der Boot-Manager braucht sie aber. Nach einem Reset startet Windows mit aktivem Secure Boot nicht mehr. Notfall-Weg ab jetzt: Secure Boot AUSSCHALTEN (Taste {0}), booten, 4_Manuell_einspielen.cmd, Secure Boot wieder an." -f $vi.Key)
}

$allDone = $hasKek2023 -and $hasWinCA2023 -and ($bootmgr2023 -ne $false)

if ($sbOn -eq $true) {
    if ($allDone) {
        Add-Finding 'Ok' 'Zertifikate (KEK, db) und Boot-Manager sind auf dem Stand 2023.'
        if (($avail -band 0x4) -ne 0) { Add-Finding 'Warn' 'KEK 2023 ist da, Windows hat es aber noch nicht registriert (AvailableUpdates 0x4): 2_Update_anstossen.cmd einmal laufen lassen.' }
    } elseif ($hasWinCA2023 -and $bootmgr2023 -eq $true -and -not $hasKek2023) {
        Add-Finding 'Warn' ("Alles erledigt AUSSER dem KEK: db hat die 2023-CAs, der Boot-Manager ist 2023-signiert. Der PC startet damit auch kuenftige 2023-signierte Boot-Medien. Der KEK 2023 braucht eine von {0} mit dem PK dieses Geraets signierte Datei - die liefert nur Windows Update (wenn nicht gesperrt) oder ein Firmware-Update des Herstellers. Folge: kuenftige db/dbx-Updates, die nur noch mit KEK 2023 signiert sind, kommen nicht an. Windows versucht es automatisch weiter." -f $vi.Vendor)
    } elseif ($recentIds -contains 1802 -or $firmwareKI) {
        Add-Finding 'Bad' ("Microsoft BLOCKIERT das Update absichtlich (Ereignis 1802, Grund: {0}). Fuer dieses Modell/BIOS ist ein Firmwarefehler bekannt, der beim Schreiben der Schluessel Probleme machen kann. Mehrfaches -Apply und Neustarten hilft hier NICHT. Loesung: neueres BIOS von {1}, das den Fehler behebt bzw. die 2023-Zertifikate mitbringt. ODER die db von Hand eintragen: SecureBootManual.ps1 (3_/4_*.cmd), danach -Apply -Force fuer den Boot-Manager." -f $(if ($firmwareKI) { $firmwareKI } else { 'Firmware_KI, steht nach dem naechsten Lauf in der Registry' }), $vi.Vendor)
    } elseif ($recentIds -contains 1803 -and -not $hasKek2023) {
        if ($hasWinCA2023) {
            Add-Finding 'Warn' ("db ist aktuell, nur der KEK fehlt: fuer dieses Modell gibt es kein von {0} PK-signiertes KEK-Update. Geraet bootet weiter. Optionen: Firmware-Update abwarten, Schluessel auf Werkseinstellung + erneut versuchen, oder eigene Schluessel (PK) einspielen." -f $vi.Vendor)
        } else {
            Add-Finding 'Bad' 'Ereignis 1803: kein PK-signiertes KEK-Update fuer dieses Modell. Der Rest (db, Boot-Manager) sollte trotzdem gehen: neu starten und erneut mit -Apply ausfuehren.'
        }
    } elseif ($recentIds -contains 1795 -or $recentIds -contains 1796) {
        Add-Finding 'Bad' ("Firmware verweigert das Schreiben. Firmware-Setup ({0}, Taste {1}): {2}. {3} Dann erneut -Apply." -f $vi.Vendor, $vi.Key, $vi.Reset, $vi.Extra)
    } elseif ($avail -ne 0) {
        Add-Finding 'Warn' 'Update laeuft noch: PC NEU STARTEN und dieses Skript erneut ausfuehren (ggf. mit -Apply). Kann 2-3 Durchgaenge brauchen.'
    } elseif (-not $Apply) {
        Add-Finding 'Warn' 'Noch nicht aktualisiert: Skript mit -Apply ausfuehren (bzw. 2_Update_anstossen.cmd).'
    } else {
        Add-Finding 'Warn' 'Neu starten und Skript erneut ausfuehren, um das Ergebnis zu pruefen.'
    }
}

Write-Host ""
Write-Host " Naechste Schritte:" -ForegroundColor Cyan
foreach ($f in $findings) {
    switch ($f.Level) { 'Ok' { Ok $f.Text } 'Bad' { Bad $f.Text } default { Warn $f.Text } }
}
Write-Host ""

# ================================================================ Uebersicht.csv
function Write-Overview {
    # Eine Zeile pro Lauf, im lokalen Ordner und im Skriptordner (z.B. Stick): Uebersicht aller Geraete
    function YN($v) { if ($v -eq $true) { 'ja' } elseif ($v -eq $false) { 'nein' } else { '?' } }
    $status = if ($noKeys) { 'nicht betroffen' }
              elseif ($pkMissing) { 'Setup Mode, PK fehlt' }
              elseif ($null -eq $sbOn) { 'kein UEFI' }
              elseif ($dbx -and -not $dbx.Valid) { 'dbx beschaedigt' }
              elseif ($allDone -and $dbx -and $dbx.Hashes -ge 50) { 'fertig' }
              elseif ($allDone) { 'fertig, dbx fehlt' }
              elseif ($hasWinCA2023 -and $bootmgr2023 -eq $true) { 'fertig ausser KEK' }
              else { 'offen' }
    $mode = if ($setup -eq 1) { 'Setup' } elseif ($setup -eq 0) { 'User' } else { '?' }
    $vals = @(
        (Get-Date -Format 'yyyy-MM-dd HH:mm'), $env:COMPUTERNAME, $serial, $cs.Manufacturer, $cs.Model,
        $bios.SMBIOSBIOSVersion, ("{0}.{1}" -f $cv.CurrentBuildNumber, $cv.UBR), $ScriptVersion,
        (YN $sbOn), $mode, (YN $hasKek2023), (YN $hasWinCA2023), (YN $hasUefiCA2023), (YN $hasOromCA2023),
        (YN $bootmgr2023), $(if ($dbx) { $dbx.Hashes } else { '' }), $(if ($dbx) { YN $dbx.Valid } else { '?' }), $status
    )
    $line = ($vals | ForEach-Object { ("$_" -replace '[;\r\n]', ',') -replace '[^\x20-\x7E]', '?' }) -join ';'
    $head = 'Datum;Hostname;Seriennummer;Hersteller;Modell;BIOS;Windows-Build;Skriptversion;SecureBoot;Modus;KEK2023;WindowsUEFICA2023;MicrosoftUEFICA2023;OptionROMCA2023;BootManager2023;dbxHashes;dbxGueltig;Status'
    $targets = @(Join-Path $localDir 'Uebersicht.csv')
    if (-not $sameDir) { $targets += Join-Path $scriptDir 'Uebersicht.csv' }
    foreach ($t in $targets) {
        try {
            if (-not (Test-Path $t)) { Set-Content -Path $t -Value $head -Encoding ASCII -ErrorAction Stop }
            Add-Content -Path $t -Value $line -Encoding ASCII -ErrorAction Stop
        } catch { Write-Host "         Uebersicht.csv nicht schreibbar: $t" -ForegroundColor Yellow }
    }
    Write-Host ("         Uebersicht.csv ergaenzt (Status: {0})" -f $status) -ForegroundColor DarkGray
}
Write-Overview
Copy-LogToScriptDir
if (-not $NoPause) { Write-Host ""; Read-Host "Enter zum Beenden" | Out-Null }
