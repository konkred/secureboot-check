<#
.SYNOPSIS
    Secure-Boot-Zertifikate (2011 -> 2023) pruefen (1_) und das Windows-Update anstossen (2_).

.DESCRIPTION
    Ohne Parameter: reine Diagnose, aendert nichts.
    Mit -Apply: BitLocker anhalten, AvailableUpdates = 0x5944, Task "Secure-Boot-Update" starten.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\SecureBootCheck.ps1
    powershell -ExecutionPolicy Bypass -File .\SecureBootCheck.ps1 -Apply -Force
#>
[CmdletBinding()]
param(
    [switch]$Apply,     # Update anstossen
    [switch]$Force,     # AvailableUpdates auch setzen, wenn bereits ein Wert ansteht
    [switch]$NoPause    # am Ende nicht auf Enter warten
)
$scriptDir = Split-Path -Parent $PSCommandPath
. (Join-Path $scriptDir 'SecureBootCommon.ps1')
Assert-Admin $PSCommandPath $PSBoundParameters
$ErrorActionPreference = 'Continue'
Initialize-Tool 'SecureBoot'

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$Level, [string]$Text) { $findings.Add([pscustomobject]@{ Level = $Level; Text = $Text }) }

function Get-EfiSignatureList([string]$Name) {
    try { $b = (Get-SecureBootUEFI -Name $Name -ErrorAction Stop).Bytes } catch { return $null }
    Parse-Esl $b
}

function Get-PeEmbeddedCerts([string]$Path) {
    # Alle Zertifikate aus den eingebetteten Authenticode-Signaturen (auch verschachtelte)
    $out = @()
    try {
        $b = [IO.File]::ReadAllBytes($Path)
        $pe = [BitConverter]::ToInt32($b, 0x3C)
        $opt = $pe + 24
        $dd = if ([BitConverter]::ToUInt16($b, $opt) -eq 0x20b) { $opt + 112 } else { $opt + 96 }
        $secOff  = [BitConverter]::ToInt32($b, $dd + 32)
        $secSize = [BitConverter]::ToInt32($b, $dd + 36)
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
    } catch { Warn "Signatur nicht lesbar: $_" }
    $out
}

function Get-ChainKind($certs) {
    $certs = @($certs)
    if ($certs.Count -eq 0) { return 'keine Signatur lesbar' }
    $names = ($certs | ForEach-Object { $_.Subject; $_.Issuer }) -join '|'
    if ($names -match 'Windows UEFI CA 2023')        { return 'Windows, 2023' }
    if ($names -match 'Windows Production PCA 2011') { return 'Windows, 2011' }
    if ($names -match 'Microsoft UEFI CA 2023')      { return 'Fremd-Bootloader, UEFI CA 2023' }
    if ($names -match 'Microsoft Corporation UEFI CA 2011') { return 'Fremd-Bootloader, UEFI CA 2011 (z.B. Linux)' }
    'unbekannt (' + (Get-CN $certs[-1].Issuer) + ')'
}

function Show-Certs($list, [string]$label) {
    if ($null -eq $list) { Bad "$label nicht lesbar"; return }
    if ($list.Certs.Count -eq 0) { Warn "$label enthaelt keine Zertifikate" }
    foreach ($c in $list.Certs) {
        $txt = "{0,-45} gueltig bis {1:yyyy-MM-dd}" -f (Get-CN $c.Subject), $c.NotAfter
        if ($c.NotAfter -lt (Get-Date)) { Warn "$txt  (abgelaufen)" } else { Ok $txt }
    }
    if ($list.Hashes -gt 0) { Info ("+ {0} SHA256-Hashes" -f $list.Hashes) }
    if ($list.Other  -gt 0) { Info ("+ {0} sonstige Eintraege" -f $list.Other) }
    if (-not $list.Valid) {
        Bad ("{0} ist BESCHAEDIGT: nur {1} von {2} Bytes sind gueltige Signaturlisten." -f $label, $list.GoodBytes, $list.Bytes)
        Add-Finding 'Bad' ("{0} ist beschaedigt. Rettung: Secure Boot aus (Taste {1}), Windows starten, 5_Sicherung_zurueckspielen.cmd. Bei der dbx hilft auch 4_Experte_Schluessel_neu_aufbauen.cmd." -f $label, $vi.Key)
    }
}

function Has-Cert($list, [string]$pattern) { if ($null -eq $list) { return $false }; [bool]($list.Certs | Where-Object { $_.Subject -match $pattern }) }

$EventInfo = @{
    1795 = 'Firmware hat das Schreiben abgelehnt'
    1796 = 'Unerwarteter Fehler beim Secure-Boot-Update'
    1797 = 'Boot-Manager-Tausch abgebrochen: Windows UEFI CA 2023 fehlt in der db'
    1799 = 'Boot-Manager mit 2023-Signatur installiert'
    1800 = 'Neustart noetig'
    1801 = 'Zertifikate aktualisiert, aber noch nicht vollstaendig angewendet'
    1802 = 'von Microsoft gesperrt (bekannter Firmwarefehler dieses Modells)'
    1803 = 'keine vom Hersteller signierte KEK-Datei fuer dieses Modell'
    1808 = 'alle Zertifikate erfolgreich aktualisiert'
}
$AvailableBits = [ordered]@{
    0x0004 = 'KEK 2023 eintragen'
    0x0040 = 'Windows UEFI CA 2023 in die db'
    0x0100 = 'Boot-Manager mit 2023-Signatur installieren'
    0x0800 = 'Microsoft UEFI CA 2023 in die db'
    0x1000 = 'Option ROM UEFI CA 2023 in die db'
    0x4000 = 'Bedingung: Fremd-CAs nur, wenn die UEFI CA 2011 vorhanden ist'
}
$sbKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot'
$svcKey = "$sbKey\Servicing"
function Get-AvailableUpdates { try { [int](Get-ItemProperty -Path $sbKey -Name AvailableUpdates -ErrorAction Stop).AvailableUpdates } catch { 0 } }
function Show-AvailableUpdates([int]$v) {
    if ($v -eq 0) { Ok "AvailableUpdates = 0x0 (nichts ausstehend)"; return }
    Warn ("AvailableUpdates = 0x{0:X}, noch ausstehend:" -f $v)
    foreach ($e in $AvailableBits.GetEnumerator()) { if ($v -band $e.Key) { Info ("  0x{0:X4}  {1}" -f $e.Key, $e.Value) } }
}
function Get-TpmWmiEvents([datetime]$Since) {
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-TPM-WMI'; StartTime = $Since } -ErrorAction Stop |
            Where-Object { $_.Id -ge 1795 -and $_.Id -le 1810 }
    } catch { @() }
}
function Get-RecentIds($evs) {
    # IDs des letzten Durchlaufs (alle Ereignisse bis 2 Minuten vor dem neuesten)
    if (-not $evs -or $evs.Count -eq 0) { return @() }
    $newest = $evs[0].TimeCreated
    @($evs | Where-Object { $_.TimeCreated -ge $newest.AddMinutes(-2) } | ForEach-Object { $_.Id } | Select-Object -Unique)
}

function Test-BootMgr {
    # Boot-Manager und Ausweich-Bootloader auf der EFI-Partition. $true = 2023, $false = 2011, $null = unklar
    $result = $null
    $letter = (68..90 | ForEach-Object { [char]$_ } | Where-Object { -not (Test-Path "$($_):\") } | Select-Object -Last 1)
    if (-not $letter) { Info "kein freier Laufwerksbuchstabe, uebersprungen"; return $null }
    $mp = "$($letter):"
    try {
        mountvol $mp /S 2>$null | Out-Null
        $bm = "$mp\EFI\Microsoft\Boot\bootmgfw.efi"
        if (Test-Path $bm) {
            $kind = Get-ChainKind (Get-PeEmbeddedCerts $bm)
            if ($kind -eq 'Windows, 2023')     { Ok "Boot-Manager (bootmgfw.efi): signiert mit Windows UEFI CA 2023"; $result = $true }
            elseif ($kind -eq 'Windows, 2011') { Warn "Boot-Manager (bootmgfw.efi): noch signiert mit Windows Production PCA 2011"; $result = $false }
            else { Warn "Boot-Manager (bootmgfw.efi): $kind" }
        } else { Warn "bootmgfw.efi nicht gefunden" }
        $fb = "$mp\EFI\Boot\bootx64.efi"
        if (Test-Path $fb) {
            $fk = Get-ChainKind (Get-PeEmbeddedCerts $fb)
            if ($fk -eq 'Windows, 2011' -and $result -eq $true) {
                Warn "Ausweich-Bootloader (bootx64.efi): noch 2011"
                Add-Finding 'Warn' 'Der Ausweich-Bootloader \EFI\Boot\bootx64.efi ist noch mit der PCA 2011 signiert. Das stoert nur, wenn die Firmware ihre Booteintraege verliert und den Ausweichpfad startet.'
            } else { Info "Ausweich-Bootloader (bootx64.efi): $fk" }
        }
    } catch { Warn "EFI-Partition nicht lesbar: $_" }
    finally { mountvol $mp /D 2>$null | Out-Null }
    $result
}

# ================================================================ 1. System
Section "1. System"
$sys = Show-SystemInfo
$cs = $sys.Cs; $bios = $sys.Bios
Info ("Firmware-Setup ({0}): Taste {1}" -f $vi.Vendor, $vi.Key)
$task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update' -ErrorAction SilentlyContinue
if (-not $task) { Bad "Geplanter Task 'Secure-Boot-Update' fehlt"; Add-Finding 'Bad' 'Windows ist zu alt (Task fehlt). Erst alle Windows-Updates installieren.' }

# ================================================================ 2. Secure Boot
Section "2. Secure-Boot-Status"
$sbOn = $null
try { $sbOn = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sbOn = $null }
$setup = $null
if ($null -ne $sbOn) { try { $setup = (Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop).Bytes[0] } catch {} }
$pkPresent = [bool](Get-VarBytes 'PK')
$otherKeys = [bool](Get-VarBytes 'KEK') -or [bool](Get-VarBytes 'db')
# Keine Schluessel und kein Secure Boot (z.B. Thin Client): nicht betroffen.
# Setup Mode MIT KEK/db, aber ohne PK: halb fertiger Neuaufbau (z.B. HP mit "Custom Keys").
$noKeys    = ($sbOn -eq $false -and $setup -eq 1 -and -not $pkPresent -and -not $otherKeys)
$pkMissing = ($setup -eq 1 -and -not $pkPresent -and $otherKeys)

if ($sbOn -eq $true) { Ok "Secure Boot ist AKTIV" }
elseif ($noKeys) {
    Info "Secure Boot ist aus und es sind keine Schluessel hinterlegt."
    Add-Finding 'Ok' 'Nicht betroffen: ohne Secure Boot prueft die Firmware keine Signaturen.'
}
elseif ($sbOn -eq $false) { Bad "Secure Boot ist AUS"; if (-not $pkMissing) { Add-Finding 'Bad' 'Secure Boot im Firmware-Setup einschalten.' } }
else { Bad "Kein UEFI (Legacy-Start)"; Add-Finding 'Warn' 'Legacy-Start ohne Secure Boot: von den Zertifikaten nicht betroffen. Fuer Secure Boot: Datentraeger mit MBR2GPT umstellen, im BIOS auf UEFI, Secure Boot an.' }

if ($null -ne $sbOn -and -not $noKeys) {
    if ($pkMissing) {
        Bad "SETUP MODE: KEK und db sind vorhanden, aber KEIN PK"
        Add-Finding 'Bad' ("Setup Mode ohne PK, Secure Boot laesst sich so nicht einschalten. Zurueck: Firmware-Setup (Taste {0}), Secure Boot aus, Werksschluessel laden (HP: Key Ownership 'HP Keys'), Windows starten, 3_Zertifikate_einspielen.cmd, Secure Boot an." -f $vi.Key)
    }
    elseif ($setup -eq 1) { Warn "SETUP MODE (keine Schluessel)"; Add-Finding 'Warn' 'Setup Mode: im Firmware-Setup Standard-Schluessel laden oder den zweiten Lauf von 4_Experte_Schluessel_neu_aufbauen.cmd ausfuehren.' }
    elseif ($setup -eq 0) { Ok "User Mode (Schluessel geladen)" }
}

# ================================================================ 3. bis 6. Schluessel
$pk = $kek = $db = $dbx = $null; $defHasWinCA2023 = $null
if ($null -ne $sbOn -and -not $noKeys) {
    Section "3. Platform Key (PK)"
    $pk = Get-EfiSignatureList 'PK'
    Show-Certs $pk 'PK'
    if ($pk -and ($pk.Certs | Where-Object { $_.Subject -match 'DO NOT TRUST|DO NOT SHIP' })) {
        Bad "PK ist ein Testschluessel (PKfail), Secure Boot ist praktisch wirkungslos"
        Add-Finding 'Bad' ("Test-PK (PKfail): BIOS-Update von {0} noetig." -f $vi.Vendor)
    }

    Section "4. Key Exchange Key (KEK)"
    $kek = Get-EfiSignatureList 'KEK'
    Show-Certs $kek 'KEK'

    Section "5. Erlaubte Signaturen (db)"
    $db = Get-EfiSignatureList 'db'
    Show-Certs $db 'db'
    $dbDef = Get-EfiSignatureList 'dbDefault'
    if ($dbDef -and $dbDef.Certs.Count) {
        $defHasWinCA2023 = Has-Cert $dbDef 'Windows UEFI CA 2023'
        if ($defHasWinCA2023) { Ok "Werkseinstellungen (dbDefault) enthalten die Windows UEFI CA 2023" }
        else { Warn "Werkseinstellungen (dbDefault) enthalten die Windows UEFI CA 2023 NICHT" }
    }

    Section "6. Sperrliste (dbx)"
    $dbx = Get-EfiSignatureList 'dbx'
    if ($dbx) {
        Info ("{0} Hash-Eintraege, {1} Zertifikate" -f $dbx.Hashes, $dbx.Certs.Count)
        if ($dbx.Unique -lt $dbx.Hashes) { Info ("davon {0} verschiedene ({1} doppelt, harmlos)" -f $dbx.Unique, ($dbx.Hashes - $dbx.Unique)) }
        if (-not $dbx.Valid) {
            Bad ("dbx ist BESCHAEDIGT: nur {0} von {1} Bytes sind gueltig" -f $dbx.GoodBytes, $dbx.Bytes)
            Add-Finding 'Bad' ("Die dbx ist beschaedigt, mit Secure Boot startet der PC dann oft nur mit 'invalid signature'. Rettung: Secure Boot aus (Taste {0}), Windows starten, 4_Experte_Schluessel_neu_aufbauen.cmd oder 5_Sicherung_zurueckspielen.cmd." -f $vi.Key)
        } elseif ($dbx.Unique -lt 50) {
            Warn "Sperrliste ist praktisch leer"
            Add-Finding 'Warn' 'Die dbx ist fast leer: bekannte unsichere Bootloader sind nicht gesperrt. Abhilfe: 3_Zertifikate_einspielen.cmd.'
        } else { Ok "Sperrliste ist in Ordnung" }
        foreach ($c in $dbx.Certs) { Info ("gesperrt: {0}" -f (Get-CN $c.Subject)) }
    } else { Warn "dbx nicht lesbar" }
}
$hasKek2023    = Has-Cert $kek 'KEK 2K CA 2023'
$hasWinCA2023  = Has-Cert $db  'Windows UEFI CA 2023'
$hasUefiCA2023 = Has-Cert $db  'Microsoft UEFI CA 2023'
$hasOromCA2023 = Has-Cert $db  'Option ROM UEFI CA 2023'

# ================================================================ 7. Boot-Manager
Section "7. Boot-Manager auf der EFI-Partition"
$bootmgr2023 = $null
if ($null -ne $sbOn -and -not $noKeys) { $bootmgr2023 = Test-BootMgr } else { Info "uebersprungen" }

# ================================================================ 8. Windows-Wartung
Section "8. Windows-Wartung (Registry, Ereignisse, BitLocker)"
$avail = Get-AvailableUpdates
Show-AvailableUpdates $avail
$firmwareKI = $null
if (Test-Path $svcKey) {
    $svc = Get-ItemProperty $svcKey
    foreach ($n in 'UEFICA2023Status', 'WindowsUEFICA2023Capable', 'ConfidenceLevel', 'UEFICA2023ErrorEvent') { if ($null -ne $svc.$n) { Info ("{0,-26} = {1}" -f $n, $svc.$n) } }
    $firmwareKI = $svc.PSObject.Properties | Where-Object { $_.Name -like '*ErrorReason' -and "$($_.Value)" -like 'Firmware_KI*' } | Select-Object -First 1 -ExpandProperty Value
    if ($firmwareKI) { Info ("Sperrgrund von Microsoft     = {0}" -f $firmwareKI) }
}
$blv = $null
try { $blv = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop } catch {}
if ($blv) { Info ("BitLocker: {0}, Schutz {1}" -f $blv.VolumeStatus, $blv.ProtectionStatus) }
$events = @(Get-TpmWmiEvents (Get-Date).AddDays(-60))
if ($events.Count) {
    Info "Ereignisse der letzten 60 Tage (neueste zuerst):"
    foreach ($e in ($events | Select-Object -First 10)) {
        $desc = if ($EventInfo.ContainsKey($e.Id)) { $EventInfo[$e.Id] } else { ($e.Message -split "`r?`n")[0] }
        $line = "{0:yyyy-MM-dd HH:mm}  {1}: {2}" -f $e.TimeCreated, $e.Id, $desc
        if ($e.Id -eq 1808) { Ok $line } elseif ($e.Id -in 1795, 1796, 1797, 1802, 1803) { Bad $line } else { Info $line }
    }
    if ($events.Count -gt 10) { Info ("... {0} weitere" -f ($events.Count - 10)) }
} else { Info "Keine Secure-Boot-Ereignisse in den letzten 60 Tagen" }
$recentIds = Get-RecentIds $events

# ================================================================ 9. Update anstossen (2_)
if ($Apply) {
    Section "9. Update anstossen"
    if ($sbOn -ne $true) { Bad "Abbruch: Secure Boot ist nicht aktiv." }
    elseif (-not $task)  { Bad "Abbruch: Task 'Secure-Boot-Update' fehlt." }
    else {
        Suspend-BitLockerOnce
        if ($avail -ne 0 -and -not $Force) { Info ("AvailableUpdates steht schon auf 0x{0:X}, bleibt so (sonst -Force)" -f $avail) }
        else { Set-ItemProperty -Path $sbKey -Name AvailableUpdates -Value 0x5944 -Type DWord; Ok "AvailableUpdates = 0x5944 gesetzt" }
        $start = Get-Date
        Start-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update'
        Info "Task gestartet, warte auf das Ende ..."
        $t = 0
        do { Start-Sleep -Seconds 3; $t += 3; $state = (Get-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update').State } while ($state -eq 'Running' -and $t -lt 180)
        Start-Sleep -Seconds 5
        Info ("Task beendet (Ergebnis 0x{0:X})" -f (Get-ScheduledTaskInfo -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update').LastTaskResult)
        $avail = Get-AvailableUpdates
        Show-AvailableUpdates $avail
        $newEvents = @(Get-TpmWmiEvents $start)
        foreach ($e in $newEvents) { Info ("NEU  {0}: {1}" -f $e.Id, $(if ($EventInfo.ContainsKey($e.Id)) { $EventInfo[$e.Id] } else { ($e.Message -split "`r?`n")[0] })) }
        if ($newEvents.Count) { $recentIds = Get-RecentIds $newEvents } else { Info "Keine neuen Ereignisse (oft erst nach dem Neustart)" }
        $kek = Get-EfiSignatureList 'KEK'; $db = Get-EfiSignatureList 'db'
        $hasKek2023    = Has-Cert $kek 'KEK 2K CA 2023'
        $hasWinCA2023  = Has-Cert $db  'Windows UEFI CA 2023'
        $hasUefiCA2023 = Has-Cert $db  'Microsoft UEFI CA 2023'
        $hasOromCA2023 = Has-Cert $db  'Option ROM UEFI CA 2023'
        $bootmgr2023 = Test-BootMgr
    }
}

# ================================================================ Ergebnis
Section "ERGEBNIS fuer $env:COMPUTERNAME ($($cs.Model))"
function Flag([bool]$v, [string]$t) { if ($v) { Ok $t } else { Bad $t } }
if ($null -ne $sbOn -and -not $noKeys) {
    Flag $hasKek2023    "KEK:  Microsoft Corporation KEK 2K CA 2023"
    Flag $hasWinCA2023  "db:   Windows UEFI CA 2023"
    Flag $hasUefiCA2023 "db:   Microsoft UEFI CA 2023"
    Flag $hasOromCA2023 "db:   Microsoft Option ROM UEFI CA 2023"
    if ($null -ne $bootmgr2023) { Flag $bootmgr2023 "Boot-Manager mit 2023 signiert" }
    if ($dbx) { Flag ($dbx.Valid -and $dbx.Unique -ge 50) ("dbx:  {0} verschiedene Hashes" -f $dbx.Unique) }
}

if ($bootmgr2023 -eq $true -and $defHasWinCA2023 -ne $true) {
    Add-Finding 'Bad' ("Kein Schluessel-Reset im Firmware-Setup mehr: Die Werkseinstellungen kennen die Windows UEFI CA 2023 nicht, danach startet Windows mit Secure Boot nicht. Notfall: Secure Boot aus (Taste {0}), Windows starten, 3_Zertifikate_einspielen.cmd, Secure Boot an." -f $vi.Key)
}
$allDone = $hasKek2023 -and $hasWinCA2023 -and ($bootmgr2023 -ne $false)
if ($sbOn -eq $true) {
    if ($allDone) {
        Add-Finding 'Ok' 'KEK, db und Boot-Manager sind auf dem Stand 2023.'
        if (($avail -band 0x4) -ne 0) { Add-Finding 'Warn' 'Windows hat den KEK 2023 noch nicht registriert: 2_Update_anstossen.cmd einmal laufen lassen.' }
    } elseif ($hasWinCA2023 -and $bootmgr2023 -eq $true) {
        Add-Finding 'Warn' ("Alles erledigt ausser dem KEK. Der PC startet auch kuenftige Boot-Medien. Den KEK 2023 kann nur eine von {0} signierte Datei eintragen, oder 4_Experte_Schluessel_neu_aufbauen.cmd, wo die Firmware das zulaesst (siehe README). Ohne KEK 2023 kommen kuenftige db- und dbx-Updates nicht an." -f $vi.Vendor)
    } elseif (-not $hasWinCA2023) {
        if ($recentIds -contains 1802 -or $firmwareKI) { Add-Finding 'Bad' 'Microsoft sperrt das automatische Update fuer dieses Modell (1802). Wiederholen hilft nicht: 3_Zertifikate_einspielen.cmd, danach 2_Update_anstossen.cmd fuer den Boot-Manager.' }
        elseif ($recentIds -contains 1795 -or $recentIds -contains 1796) { Add-Finding 'Bad' ("Die Firmware verweigert das Schreiben. Im Firmware-Setup (Taste {0}) pruefen, ob Secure Boot geschuetzt ist, dann 3_Zertifikate_einspielen.cmd." -f $vi.Key) }
        elseif ($avail -ne 0) { Add-Finding 'Warn' 'Update laeuft noch: neu starten und erneut pruefen, kann 2 bis 3 Durchgaenge brauchen.' }
        else { Add-Finding 'Warn' 'Noch nicht aktualisiert: 2_Update_anstossen.cmd, bei Sperre 3_Zertifikate_einspielen.cmd.' }
    } else {
        Add-Finding 'Warn' 'db ist aktuell, der Boot-Manager noch nicht: 2_Update_anstossen.cmd, danach neu starten und erneut pruefen.'
    }
}
Write-Host ""
Write-Host " Naechste Schritte:" -ForegroundColor Cyan
foreach ($f in $findings) { Show-Level $f.Level $f.Text }
Write-Host ""

# ================================================================ Uebersicht.csv
function YN($v) { if ($v -eq $true) { 'ja' } elseif ($v -eq $false) { 'nein' } else { '?' } }
$status = if ($noKeys) { 'nicht betroffen' }
          elseif ($pkMissing) { 'Setup Mode, PK fehlt' }
          elseif ($null -eq $sbOn) { 'kein UEFI' }
          elseif ($dbx -and -not $dbx.Valid) { 'dbx beschaedigt' }
          elseif ($allDone -and $dbx -and $dbx.Unique -ge 50) { 'fertig' }
          elseif ($allDone) { 'fertig, dbx fehlt' }
          elseif ($hasWinCA2023 -and $bootmgr2023 -eq $true) { 'fertig ausser KEK' }
          else { 'offen' }
$mode = if ($setup -eq 1) { 'Setup' } elseif ($setup -eq 0) { 'User' } else { '?' }
Add-CsvLine 'Uebersicht.csv' 'Datum;Hostname;Seriennummer;Hersteller;Modell;BIOS;Windows-Build;Skriptversion;SecureBoot;Modus;KEK2023;WindowsUEFICA2023;MicrosoftUEFICA2023;OptionROMCA2023;BootManager2023;dbxHashes;dbxGueltig;Status' @(
    (Get-Date -Format 'yyyy-MM-dd HH:mm'), $env:COMPUTERNAME, $serial, $cs.Manufacturer, $cs.Model, $bios.SMBIOSBIOSVersion, $sys.Build, $ToolVersion,
    (YN $sbOn), $mode, (YN $hasKek2023), (YN $hasWinCA2023), (YN $hasUefiCA2023), (YN $hasOromCA2023), (YN $bootmgr2023),
    $(if ($dbx) { $dbx.Unique } else { '' }), $(if ($dbx) { YN $dbx.Valid } else { '?' }), $status)
Write-Host ("         Uebersicht.csv ergaenzt (Status: {0})" -f $status) -ForegroundColor DarkGray
Finish
