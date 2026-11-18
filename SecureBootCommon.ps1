<#
    SecureBootCommon.ps1 - gemeinsame Funktionen fuer alle Skripte des Werkzeugkastens.
    Wird von den Skripten per Dot-Sourcing geladen und nicht selbst gestartet.

    Erwartet vom aufrufenden Skript:  $scriptDir, $NoPause
#>

$ToolVersion = '2.0'

# ---------------------------------------------------------------- Rechte
function Assert-Admin([string]$ScriptPath, [System.Collections.IDictionary]$Bound) {
    # Startet das Skript mit Administratorrechten neu und gibt alle Parameter weiter
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) { return }
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"")
    foreach ($k in $Bound.Keys) {
        $v = $Bound[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $a += "-$k" } }
        elseif ($null -ne $v -and "$v" -ne '') { $a += @("-$k", "`"$v`"") }
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a
    exit
}

# ---------------------------------------------------------------- Ausgabe
function Section([string]$t) { Write-Host ""; Write-Host ("=" * 70) -ForegroundColor DarkCyan; Write-Host " $t" -ForegroundColor Cyan; Write-Host ("=" * 70) -ForegroundColor DarkCyan }
function Ok([string]$t)   { Write-Host "  [OK]   $t" -ForegroundColor Green }
function Bad([string]$t)  { Write-Host "  [!!]   $t" -ForegroundColor Red }
function Warn([string]$t) { Write-Host "  [??]   $t" -ForegroundColor Yellow }
function Info([string]$t) { Write-Host "         $t" }
function Show-Level([string]$Level, [string]$t) { switch ($Level) { 'Ok' { Ok $t } 'Bad' { Bad $t } 'Warn' { Warn $t } default { Info $t } } }
function Confirm-JA([string]$q) { (Read-Host "$q  Zum Bestaetigen JA tippen") -ceq 'JA' }

# ---------------------------------------------------------------- Geraet und Ablage
# Alles wird zuerst LOKAL geschrieben (ueberlebt einen abgezogenen Stick) und am Ende in den
# gleichen Unterordner neben den Skripten kopiert:  Logs\<PC>\  Backups\<PC>\  Rebuild\<PC>\
# <PC> = Hostname_Seriennummer, damit geklonte PCs mit gleichem Namen getrennt bleiben.
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

function Initialize-Tool([string]$LogPrefix) {
    $script:localDir = Join-Path $env:ProgramData 'SecureBootCheck'
    $script:sameDir  = ($scriptDir.TrimEnd('\') -eq $script:localDir.TrimEnd('\'))
    $script:serial   = Get-Serial
    $script:deviceId = if ($script:serial) { "{0}_{1}" -f $env:COMPUTERNAME, $script:serial } else { $env:COMPUTERNAME }
    $script:logFile  = Join-Path (Get-SubDir $script:localDir 'Logs') ("{0}_{1}_{2}.txt" -f $LogPrefix, $script:deviceId, (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'))
    try { Start-Transcript -Path $script:logFile -Force | Out-Null } catch { Write-Warning "Kein Protokoll moeglich: $_" }
    $script:vi = Get-VendorInfo
}

function Get-SubDir([string]$Root, [string]$Kind) { $d = Join-Path (Join-Path $Root $Kind) $deviceId; New-Item -ItemType Directory -Path $d -Force -ErrorAction SilentlyContinue | Out-Null; $d }

function Copy-ToScriptDir([string]$Path, [string]$Kind) {
    if ($sameDir -or -not (Test-Path $Path)) { return $null }
    try { $dest = Get-SubDir $scriptDir $Kind; Copy-Item -Path $Path -Destination $dest -Recurse -Force -ErrorAction Stop; $dest } catch { $null }
}

function Add-CsvLine([string]$FileName, [string]$Header, [object[]]$Values) {
    # Haengt eine Zeile an eine Uebersicht an, lokal und im Skriptordner
    $line = ($Values | ForEach-Object { ("$_" -replace '[;\r\n]', ',') -replace '[^\x20-\x7E]', '?' }) -join ';'
    $targets = @(Join-Path $localDir $FileName)
    if (-not $sameDir) { $targets += Join-Path $scriptDir $FileName }
    foreach ($t in $targets) {
        try {
            if (-not (Test-Path $t)) { Set-Content -Path $t -Value $Header -Encoding ASCII -ErrorAction Stop }
            Add-Content -Path $t -Value $line -Encoding ASCII -ErrorAction Stop
        } catch { Write-Host "         $FileName nicht schreibbar: $t" -ForegroundColor Yellow }
    }
}

function Finish {
    if ($script:backupDir) { $d = Copy-ToScriptDir $script:backupDir 'Backups'; if ($d) { Write-Host "         Sicherung kopiert nach: $d" -ForegroundColor DarkGray } }
    try { Stop-Transcript | Out-Null } catch {}
    $d = Copy-ToScriptDir $logFile 'Logs'
    if ($d) { Write-Host "         Protokoll kopiert nach: $d" -ForegroundColor DarkGray }
    elseif (-not $sameDir) { Write-Host "         Kopieren in den Skriptordner fehlgeschlagen" -ForegroundColor Yellow }
    Write-Host "         Lokales Protokoll:      $logFile" -ForegroundColor DarkGray
    if (-not $sameDir) { Write-Host "         Stick vor dem Abziehen bitte 'sicher entfernen'." -ForegroundColor DarkGray }
    if (-not $NoPause) { Write-Host ""; Read-Host "Enter zum Beenden" | Out-Null }
    exit
}

function Show-SystemInfo {
    # Kopf jedes Protokolls: Geraet, Seriennummer, BIOS, Windows
    $cs   = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $cv   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [int]$cv.CurrentBuildNumber
    $prod  = "$($cv.ProductName)"
    if ($build -ge 22000) { $prod = $prod -replace 'Windows 10', 'Windows 11' }
    Info ("Skript:     Version {0}" -f $ToolVersion)
    Info ("Hersteller: {0}" -f $cs.Manufacturer)
    Info ("Modell:     {0}" -f $cs.Model)
    Info ("Seriennr.:  {0}" -f $(if ($serial) { $serial } else { 'nicht auslesbar' }))
    Info ("PC:         {0}  (Ordner {1})" -f $env:COMPUTERNAME, $deviceId)
    $biosDate = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') } else { '?' }
    Info ("BIOS:       {0}  ({1})" -f $bios.SMBIOSBIOSVersion, $biosDate)
    Info ("Windows:    {0} {1}, Build {2}.{3}" -f $prod, $cv.DisplayVersion, $cv.CurrentBuildNumber, $cv.UBR)
    [pscustomobject]@{ Cs = $cs; Bios = $bios; Cv = $cv; Model = "$($cs.Manufacturer) $($cs.Model)"; Windows = ("{0} {1}" -f $prod, $cv.DisplayVersion); Build = ("{0}.{1}" -f $cv.CurrentBuildNumber, $cv.UBR) }
}

# ---------------------------------------------------------------- Hersteller
function Get-VendorInfo {
    # Taste fuers Firmware-Setup und typischer Weg zum Zuruecksetzen der Schluessel
    $cs = Get-CimInstance Win32_ComputerSystem
    $m = "$($cs.Manufacturer)"; $mo = "$($cs.Model)"
    $v = [pscustomobject]@{ Vendor = $m.Trim(); Key = 'F2, F10, F1 oder Entf'; Reset = 'Secure Boot -> Schluessel auf Werkseinstellung (Restore Factory / Default Keys)'; Clear = 'Firmware-Setup -> Secure Boot -> "Clear / Delete all keys" bzw. "Setup Mode"' }
    if ($mo -match 'Virtual Machine' -and $m -match 'Microsoft') {
        $v.Vendor = 'Hyper-V'; $v.Key = '(VM ausgeschaltet) Hyper-V-Manager'; $v.Reset = 'VM-Einstellungen -> Sicherheit -> Secure Boot aus, oder VM neu anlegen'; $v.Clear = 'nicht moeglich'
    } elseif ($m -match 'VMware') {
        $v.Vendor = 'VMware'; $v.Key = '(VM ausgeschaltet) VM-Einstellungen'; $v.Reset = 'NVRAM-Datei (.nvram) loeschen'; $v.Clear = 'NVRAM-Datei (.nvram) loeschen'
    } elseif ($m -match 'HP|Hewlett') {
        $v.Vendor = 'HP'; $v.Key = 'F10'; $v.Reset = 'Advanced (aeltere Modelle: Security) -> Secure Boot Configuration -> Schluessel auf Werkseinstellung'
        $v.Clear = 'F10 -> Advanced bzw. Security -> Secure Boot Configuration -> "Clear Secure Boot Keys" (Bestaetigungscode eingeben)'
    } elseif ($m -match 'Dell') {
        $v.Vendor = 'Dell'; $v.Key = 'F2'; $v.Reset = 'Secure Boot -> Expert Key Management -> Restore Settings (Factory)'; $v.Clear = 'F2 -> Secure Boot -> Expert Key Management -> Custom Mode an -> "Delete All Keys"'
    } elseif ($m -match 'Lenovo') {
        $v.Vendor = 'Lenovo'; $v.Key = 'F1 (ThinkPad/ThinkCentre) bzw. F2'; $v.Reset = 'Security -> Secure Boot -> Restore Factory Keys'; $v.Clear = 'F1/F2 -> Security -> Secure Boot -> "Reset to Setup Mode" bzw. "Clear All Secure Boot Keys"'
    } elseif ($m -match 'Fujitsu') {
        $v.Vendor = 'Fujitsu'; $v.Key = 'F2'; $v.Reset = 'Security -> Secure Boot Configuration -> Restore Factory Keys'; $v.Clear = 'F2 -> Security -> Secure Boot Configuration -> "Delete all Secure Boot Variables"'
    } elseif ($m -match 'Microsoft' -and $mo -match 'Surface') {
        $v.Vendor = 'Microsoft Surface'; $v.Key = 'Lauter-Taste beim Einschalten halten'; $v.Reset = 'Security -> Secure Boot -> Microsoft Only / Default'
    } elseif ($m -match 'ASUS|ASRock|Micro-Star|MSI|Gigabyte') {
        $v.Key = 'Entf / F2'; $v.Reset = 'Boot -> Secure Boot -> Key Management -> Restore Factory Keys'; $v.Clear = 'Entf -> Boot -> Secure Boot -> Key Management -> "Clear Secure Boot Keys"'
    } elseif ($m -match 'Google' -or "$((Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion)" -match 'MrChromebox') {
        $v.Vendor = 'Chromebox (MrChromebox-UEFI)'; $v.Key = 'Esc beim Start'; $v.Reset = 'Device Manager -> Secure Boot Configuration -> Reset Secure Boot Keys'; $v.Clear = 'Esc -> Device Manager -> Secure Boot Configuration -> Mode "Custom" -> PK Options -> Delete PK'
    } elseif ($m -match 'Acer') {
        $v.Vendor = 'Acer'; $v.Key = 'F2'; $v.Reset = 'Security -> Restore Secure Boot to Factory Default (ggf. erst Supervisor-Passwort setzen)'
    }
    $v
}

function Suspend-BitLockerOnce {
    try {
        $blv = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ($blv.ProtectionStatus -eq 'On') { Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 3 -ErrorAction Stop | Out-Null; Ok "BitLocker fuer 3 Neustarts angehalten" }
    } catch {}
}

# ---------------------------------------------------------------- Signaturlisten (EFI_SIGNATURE_LIST)
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
$X509Guid    = [Guid]'a5c059a1-94e4-4aa7-87b5-ab155c2bf072'
$Sha256Guid  = [Guid]'c1c41626-504c-4092-aca9-41f936934328'
$Pkcs7Guid   = [Guid]'4aafd29d-68df-49ee-8aa9-347d375665a7'
$MsOwnerGuid = [Guid]'77fa9abd-0359-4d32-bd60-28f4e78f784b'

function Get-CN([string]$dn) { if ($dn -match 'CN=([^,]+)') { $Matches[1].Trim() } else { $dn } }
function Get-VarBytes([string]$Name) { try { (Get-SecureBootUEFI -Name $Name -ErrorAction Stop).Bytes } catch { $null } }
function Join-Bytes { param([object[]]$Parts) $l = New-Object System.Collections.Generic.List[byte]; foreach ($p in $Parts) { if ($p) { $l.AddRange([byte[]]$p) } }; ,$l.ToArray() }

function Parse-Esl([byte[]]$b) {
    # Zertifikate, Anzahl Hashes (gesamt und verschieden), sonstige Eintraege.
    # Valid = die Daten bestehen vollstaendig aus sauberen Signaturlisten (kein Rest, kein Muell).
    $certs = @(); $hashes = 0; $other = 0; $o = 0
    $uniq = New-Object 'System.Collections.Generic.HashSet[string]'
    if (-not $b) { return [pscustomobject]@{ Certs = @(); Hashes = 0; Unique = 0; Other = 0; Valid = $true; Bytes = 0; GoodBytes = 0 } }
    while ($o + 28 -le $b.Length) {
        $type     = New-Object Guid (,[byte[]]$b[$o..($o + 15)])
        $listSize = [BitConverter]::ToUInt32($b, $o + 16)
        $hdrSize  = [BitConverter]::ToUInt32($b, $o + 20)
        $sigSize  = [BitConverter]::ToUInt32($b, $o + 24)
        if ($listSize -lt 28 -or $sigSize -lt 16 -or ($o + $listSize) -gt $b.Length) { break }
        $p = $o + 28 + $hdrSize
        while ($p + $sigSize -le $o + $listSize) {
            if ($type -eq $X509Guid) {
                try { $certs += New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,[byte[]]$b[($p + 16)..($p + $sigSize - 1)]) } catch { $other++ }
            } elseif ($type -eq $Sha256Guid) {
                $hashes++
                if ($sigSize -ge 48) { [void]$uniq.Add([BitConverter]::ToString($b, $p + 16, 32)) }
            } else { $other++ }
            $p += $sigSize
        }
        $o += $listSize
    }
    [pscustomobject]@{ Certs = $certs; Hashes = $hashes; Unique = $uniq.Count; Other = $other; Valid = ($o -eq $b.Length); Bytes = $b.Length; GoodBytes = $o }
}

function Get-EslHashes([byte[]]$b) {
    # alle SHA256-Eintraege als Hex-Text, um "was ist neu" zu bestimmen
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    $o = 0
    if (-not $b) { return ,$set }
    while ($o + 28 -le $b.Length) {
        $type     = New-Object Guid (,[byte[]]$b[$o..($o + 15)])
        $listSize = [BitConverter]::ToUInt32($b, $o + 16)
        $hdrSize  = [BitConverter]::ToUInt32($b, $o + 20)
        $sigSize  = [BitConverter]::ToUInt32($b, $o + 24)
        if ($listSize -lt 28 -or $sigSize -lt 16 -or ($o + $listSize) -gt $b.Length) { break }
        if ($type -eq $Sha256Guid -and $sigSize -ge 48) {
            $p = $o + 28 + $hdrSize
            while ($p + $sigSize -le $o + $listSize) { [void]$set.Add([BitConverter]::ToString($b, $p + 16, 32)); $p += $sigSize }
        }
        $o += $listSize
    }
    ,$set
}

function Get-CleanDbx([byte[]]$b) {
    # Behaelt nur saubere SHA256-Hashlisten; Zertifikate, unbekannte Typen und Muell fallen weg
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

function Get-DedupDbx([byte[]]$b) {
    # Fasst alle SHA256-Eintraege zu EINER Liste zusammen, jeder Hash nur einmal (spart Firmware-Speicher)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $ms = New-Object IO.MemoryStream; $n = 0; $o = 0
    while ($b -and $o + 28 -le $b.Length) {
        $type     = New-Object Guid (,[byte[]]$b[$o..($o + 15)])
        $listSize = [BitConverter]::ToUInt32($b, $o + 16)
        $hdrSize  = [BitConverter]::ToUInt32($b, $o + 20)
        $sigSize  = [BitConverter]::ToUInt32($b, $o + 24)
        if ($listSize -lt 28 -or $sigSize -lt 16 -or ($o + $listSize) -gt $b.Length) { break }
        if ($type -eq $Sha256Guid -and $sigSize -eq 48) {
            $p = $o + 28 + $hdrSize
            while ($p + 48 -le $o + $listSize) {
                if ($seen.Add([BitConverter]::ToString($b, $p + 16, 32))) { $ms.Write($b, $p, 48); $n++ }
                $p += 48
            }
        }
        $o += $listSize
    }
    if ($n -eq 0) { return ,([byte[]]@()) }
    $hdr = New-Object IO.MemoryStream; $w = New-Object IO.BinaryWriter $hdr
    $w.Write($Sha256Guid.ToByteArray()); $w.Write([UInt32](28 + 48 * $n)); $w.Write([UInt32]0); $w.Write([UInt32]48)
    $w.Write($ms.ToArray()); $w.Flush()
    ,$hdr.ToArray()
}

# ---------------------------------------------------------------- Signierte Update-Dateien (EFI_VARIABLE_AUTHENTICATION_2)
function Unwrap-Content([byte[]]$c) {
    # Aeltere Microsoft-Dateien haben vor der Signaturliste noch Variablenname (UTF-16),
    # Hersteller-GUID, Attribute und Zeitstempel. Das wird hier abgeschnitten.
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

function Get-Cms([byte[]]$sig) {
    # Die Signatur ist oft nacktes SignedData ohne ContentInfo, dann wird sie eingepackt
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    try { $cms.Decode($sig); return $cms } catch {}
    try {
        $oid = [byte[]](0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02)
        function DerLen([int]$n) { if ($n -lt 128) { ,[byte[]]@($n) } elseif ($n -lt 256) { ,[byte[]]@(0x81,$n) } else { ,[byte[]]@(0x82, ($n -shr 8), ($n -band 0xFF)) } }
        $a0  = [byte[]](@(0xA0) + (DerLen $sig.Length) + $sig)
        $seq = [byte[]]($oid + $a0)
        $ci  = [byte[]](@(0x30) + (DerLen $seq.Length) + $seq)
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $cms.Decode($ci)
        return $cms
    } catch { return $null }
}

function Get-Signers([byte[]]$sig) {
    $cms = Get-Cms $sig
    if (-not $cms) { return @() }
    @($cms.SignerInfos | ForEach-Object { if ($_.Certificate) { Get-CN $_.Certificate.Subject } })
}

function Get-SignerKek([byte[]]$sig) {
    # Mit welchem Microsoft-KEK ist die Datei signiert? Die Firmware nimmt sie nur an, wenn dieser KEK eingetragen ist.
    $cms = Get-Cms $sig
    if (-not $cms) { return '?' }
    $names = (@($cms.Certificates) | ForEach-Object { $_.Subject; $_.Issuer }) -join '|'
    if ($names -match 'KEK 2K CA 2023') { return '2023' }
    if ($names -match 'KEK CA 2011')    { return '2011' }
    '?'
}

function Read-AuthPayload([string]$Path) {
    # Aufbau: Zeitstempel (16 Bytes) + WIN_CERTIFICATE_UEFI_GUID mit PKCS7-Signatur + Inhalt
    $b = [IO.File]::ReadAllBytes($Path)
    if ($b.Length -lt 48) { return $null }
    $year     = [BitConverter]::ToUInt16($b, 0)
    $dwLength = [BitConverter]::ToUInt32($b, 16)
    if ($year -lt 2000 -or $year -gt 2100 -or [BitConverter]::ToUInt16($b, 22) -ne 0x0EF1) { return $null }
    if ((New-Object Guid (,[byte[]]$b[24..39])) -ne $Pkcs7Guid) { return $null }
    $contentStart = 16 + $dwLength
    if ($contentStart -ge $b.Length) { return $null }
    try { $dt = New-Object DateTime ($year, $b[2], $b[3], $b[4], $b[5], $b[6]) } catch { return $null }
    $sig = [byte[]]$b[40..($contentStart - 1)]
    $uw  = Unwrap-Content ([byte[]]$b[$contentStart..($b.Length - 1)])
    $esl = Parse-Esl $uw.Content
    [pscustomobject]@{
        File     = $Path
        Name     = Split-Path -Leaf $Path
        Time     = $dt.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        Sig      = $sig
        Content  = $uw.Content
        Certs    = $esl.Certs
        Hashes   = $esl.Hashes
        Other    = $esl.Other
        Valid    = $esl.Valid
        Wrapped  = $uw.Wrapped
        Signers  = Get-Signers $sig
        SignedBy = Get-SignerKek $sig
    }
}

function Get-PayloadTarget($p) {
    # Zuerst nach Dateiname (dbx-Dateien koennen auch Zertifikate enthalten = Sperrung), dann nach Inhalt
    if     ($p.Name -match 'dbx')                                { return 'dbx' }
    elseif ($p.Name -match 'kek')                                { return 'KEK' }
    elseif ($p.Certs | Where-Object { $_.Subject -match 'KEK' }) { return 'KEK' }
    elseif ($p.Certs.Count -gt 0)                                { return 'db'  }
    elseif ($p.Hashes -gt 0)                                     { return 'dbx' }
    '?'
}

function Get-SkipReason($p, [string]$Target, [int]$MissingCount, [bool]$HasKek2023 = $true) {
    # $null = darf per Anhaengen eingespielt werden, sonst der Grund fuers Ueberspringen
    if ($p.Name -match 'DBXUpdate2024') { return 'sperrt die alte Windows-CA 2011, wird NIE eingespielt' }
    if (-not $p.Valid)   { return 'Format nicht sauber erkannt' }
    if ($p.Other -gt 0)  { return 'unbekannte Eintragstypen' }
    if ($Target -eq '?') { return 'Inhalt nicht erkannt' }
    if ($p.SignedBy -eq '2023' -and -not $HasKek2023) { return 'mit dem KEK 2023 signiert, der hier fehlt' }
    if ($Target -eq 'dbx' -and ($p.Certs | Where-Object { $_.Subject -match 'Production PCA 2011' })) { return 'sperrt die alte Windows-CA 2011, wird NIE eingespielt' }
    if ($Target -eq 'dbx' -and $p.Certs.Count -gt 0) { return 'dbx mit Zertifikaten, nicht automatisch' }
    if ($Target -eq 'dbx' -and $p.Name -match 'SVN') { return 'SVN-Eintrag, das regelt Windows selbst' }
    if ($Target -eq 'dbx' -and $p.Hashes -eq 0) { return 'keine Hashes' }
    if ($Target -eq 'dbx' -and $p.Name -match '(ia32|x86|arm|aarch64)' -and $p.Name -notmatch 'x64|amd64') { return 'andere Prozessorarchitektur' }
    if ($Target -ne 'dbx' -and $MissingCount -eq 0) { return 'bereits vorhanden' }
    $null
}

function Get-DbxSkipReason($p) {
    # Fuer den Neuaufbau (4_): welche Hashes in die neue dbx duerfen. Signatur spielt dort keine Rolle.
    if ($p.Name -match 'DBXUpdate2024')    { return 'PCA-2011-Sperre, NIE' }
    if (-not $p.Valid -or $p.Other -gt 0) { return 'Format nicht sauber erkannt' }
    if ($p.Certs.Count -gt 0)             { return 'enthaelt Zertifikate' }
    if ($p.Hashes -eq 0)                  { return 'keine Hashes' }
    $null
}
