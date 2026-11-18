# Secure Boot: Zertifikate von 2011 auf 2023 umstellen

Die Microsoft-Zertifikate, mit denen Secure Boot seit 2012 arbeitet, laufen 2026 ab. Windows soll
die Nachfolger von 2023 selbst einspielen, scheitert aber auf vielen älteren PCs an der Firmware
oder an einer Sperre von Microsoft. Diese Skripte zeigen, wo ein PC steht, stoßen das Windows-Update
an und tragen die neuen Zertifikate bei Bedarf von Hand ein. Dazu gibt es eine Prüfung der
Windows-11-Voraussetzungen.

Die Kurzanleitung für den USB-Stick ist [`LIESMICH.txt`](LIESMICH.txt).

## Anleitung

Alle `.cmd`-Dateien per Doppelklick starten, sie fordern selbst Administratorrechte an. Vom
USB-Stick aus den Stick vor dem Abziehen über „Hardware sicher entfernen“ abmelden, sonst fehlen
Protokolle.

| Datei | Wirkung |
|---|---|
| `1_Pruefen.cmd` | zeigt den Stand, ändert nichts |
| `2_Update_anstossen.cmd` | lässt Windows die Zertifikate und den Boot-Manager selbst einspielen |
| `3_Zertifikate_einspielen.cmd` | trägt die 2023-Zertifikate und die Sperrliste von Hand ein, nach Bestätigung mit `JA` |
| `4_Experte_Schluessel_neu_aufbauen.cmd` | baut die Schlüssel über den Setup Mode neu auf, auch mit KEK 2023 |
| `5_Sicherung_zurueckspielen.cmd` | schreibt eine frühere Sicherung zurück |
| `6_Windows11_Voraussetzungen_pruefen.cmd` | prüft, ob und wie gut Windows 11 auf dem PC läuft, ändert nichts |

### Der normale Ablauf

1. `1_Pruefen.cmd`. Ist alles grün, ist nichts zu tun.
2. `2_Update_anstossen.cmd`, neu starten, `1_Pruefen.cmd`. Oft ist es damit schon erledigt.
3. Hängt es (Microsoft-Sperre 1802, Firmware lehnt ab): `3_Zertifikate_einspielen.cmd`. Das Skript
   zeigt zuerst den Plan und schreibt erst nach `JA`.
4. Neu starten, `2_Update_anstossen.cmd` für den Boot-Manager, neu starten, `1_Pruefen.cmd`.

Fertig ist ein PC, wenn die db die Windows UEFI CA 2023 enthält und der Boot-Manager damit signiert
ist. Der KEK 2023 und eine volle Sperrliste (rund 300 Hashes) sind die Kür. Fehlt nur der KEK 2023,
startet der PC trotzdem normal. Wer ihn haben will, kann `4_Experte_Schluessel_neu_aufbauen.cmd`
versuchen, sofern die Firmware das mitmacht (siehe [Getestete Geräte](#getestete-geräte)).

### Notfall

> ⚠️ **Nach dem Tausch des Boot-Managers die Secure-Boot-Schlüssel im BIOS nie mehr löschen oder
> auf Werkseinstellung setzen.** Die Werkseinstellungen der meisten älteren Geräte kennen die
> Windows UEFI CA 2023 nicht, danach startet Windows mit Secure Boot nicht mehr. `1_Pruefen.cmd`
> sagt, ob das bei diesem PC zutrifft.

Startet ein PC nach einem Schritt nicht (z.B. „invalid signature“):

1. Ins Firmware-Setup und Secure Boot ausschalten. Das ist immer gefahrlos. Die Taste nennt
   `1_Pruefen.cmd` (HP: F10, Lenovo: F1, MrChromebox: Esc).
2. Windows starten, `3_Zertifikate_einspielen.cmd`.
3. Secure Boot wieder einschalten.

Alternativ holt `5_Sicherung_zurueckspielen.cmd` den Stand vor dem letzten Schreiben zurück.

> ⚠️ **Nie einspielen:** `DBXUpdate2024.bin` und `DBXUpdate2024Legacy.bin` sperren die alte
> Windows Production PCA 2011. Danach starten ältere Boot-Manager, Installationsmedien und
> Rettungssticks nicht mehr. Die Skripte überspringen diese Dateien immer.

## Die Werkzeuge

### `1_Pruefen.cmd` und `2_Update_anstossen.cmd`

`1_` liest alles aus: System, Secure-Boot-Status, PK, KEK, db und dbx mit Ablaufdaten, die
Werkseinstellungen (`dbDefault`), den Boot-Manager auf der EFI-Partition, die Windows-Wartung
(Registry, Ereignisse, BitLocker). Jede Variable wird auf ein sauberes Format geprüft. Am Ende stehen
die nächsten Schritte, und eine Zeile wird an `Uebersicht.csv` angehängt (Status wie `fertig`,
`fertig ausser KEK`, `offen`, `dbx beschaedigt`). Die Datei lässt sich in Excel öffnen und zeigt,
welche PCs noch fehlen.

`2_` setzt `AvailableUpdates` auf `0x5944`, startet den Task `Secure-Boot-Update` und prüft danach
erneut. Das ist der Weg, den Windows von sich aus geht, nur sofort. Bei einer Microsoft-Sperre trägt
er nichts in die db ein. Steht die Windows UEFI CA 2023 aber schon drin, tauscht er den Boot-Manager.

### `3_Zertifikate_einspielen.cmd`

1. sichert PK, KEK, db und dbx nach `Backups\<PC>\`,
2. liest jede von Microsoft signierte Datei aus `SecureBootUpdates` und zeigt, was wohin gehört und
   was übersprungen wird (schon vorhanden, falsch signiert, PCA-2011-Sperre),
3. hängt nach `JA` alles an: zuerst die Windows UEFI CA 2023, dann die übrigen db-Zertifikate, den
   KEK (klappt nur mit einer Datei des Herstellers) und zuletzt die Sperrliste.

Die Firmware nimmt eine Datei nur an, wenn sie mit einem bei ihr eingetragenen Microsoft-KEK signiert
ist. Neuere Windows-Versionen bringen die Sperrliste nur noch mit dem KEK 2023 signiert mit. Fehlt
der KEK 2023, nimmt das Skript stattdessen die gleichwertigen, mit dem KEK 2011 signierten Dateien
aus dem Ordner `dbx_KEK2011` neben den Skripten. Ist der Ordner leer, bietet es an, die drei Dateien
von Microsoft herunterzuladen
([microsoft/secureboot_objects](https://github.com/microsoft/secureboot_objects),
`PostSignedObjects/SignedByKEK2011/dbx_x64_Legacy`). Sie enthalten zusammen dieselben Hashes.
Heruntergeladene Dateien werden geprüft und nur behalten, wenn sie wirklich KEK-2011-signierte
Sperrlisten sind.

Den KEK 2023 kann dieser Weg nicht eintragen, dafür bräuchte es eine Signatur mit dem PK des
Herstellers.

### `4_Experte_Schluessel_neu_aufbauen.cmd`

Löscht man im Firmware-Setup alle Schlüssel, geht die Firmware in den **Setup Mode** und prüft beim
Schreiben keine Signaturen. Das Skript läuft deshalb zweimal:

1. **Erster Lauf** (User Mode): ergänzt KEK (um den KEK 2023), db und dbx und speichert alles in
   `Rebuild\<PC>\`, die Originale in `Rebuild\<PC>\Original\`.
2. Neustart, im Firmware-Setup die Schlüssel löschen (HP: „Clear Secure Boot Keys“, Lenovo: „Reset
   to Setup Mode“), Windows starten.
3. **Zweiter Lauf** (Setup Mode): schreibt db, dbx, KEK und zuletzt den originalen PK. Damit ist die
   Firmware wieder im User Mode.
4. Neustart, `1_Pruefen.cmd`.

Wie die Firmware mit dem zurückgeschriebenen PK umgeht, ist je nach Hersteller verschieden:

| Verhalten | Beispiel | Folge |
|---|---|---|
| nimmt den PK an, User Mode erst nach dem Neustart | Lenovo ThinkCentre M93 | alles bleibt erhalten |
| lehnt den PK ab, setzt beim Neustart ihren Werks-PK selbst | HP ProDesk 400 G5, EliteBook 840 G3 | KEK und db bleiben, die dbx fällt zurück: danach `3_` |
| lädt beim Löschen die Werksschlüssel (Key Ownership „HP Keys“) oder lehnt den PK ab und bleibt ohne PK im Setup Mode („Custom Keys“) | HP Compaq Pro 6300 | geht nicht, das Skript warnt auf diesem Modell |

Rückweg, wenn Secure Boot sich nicht mehr einschalten lässt: Secure Boot aus, Werksschlüssel laden
(HP: Key Ownership „HP Keys“), Windows starten, `3_Zertifikate_einspielen.cmd`, Secure Boot an.
`1_Pruefen.cmd` erkennt den Zustand „Setup Mode ohne PK“ und nennt diesen Weg.

### `5_Sicherung_zurueckspielen.cmd`

Zur Auswahl stehen alle Sicherungen dieses Geräts: `Backups\<PC>\Backup_*` (von `3_`) und
`Rebuild\<PC>\Original` (von `4_`). Wie bei `4_` geht das nur im Setup Mode: einmal starten (zeigt
die Sicherungen und wie man die Schlüssel löscht), Schlüssel löschen, Windows starten, erneut starten
und die Nummer wählen.

### `6_Windows11_Voraussetzungen_pruefen.cmd`

Zeigt Hersteller, Modell, Seriennummer und Windows-Version und bewertet:

| Bereich | grün | gelb | rot |
|---|---|---|---|
| Prozessor | steht auf Microsofts Liste (Intel ab 8. Generation, Ryzen ab 2000) | läuft, ist aber nicht offiziell (z.B. Intel Core i der 1. bis 7. Generation, Ryzen 1000, FX) | ohne SSE4.2/POPCNT (z.B. Core 2 Duo, Phenom), 32 Bit: Windows 11 ab 24H2 startet nicht |
| Arbeitsspeicher | mehr als 8 GB | 4 bis 8 GB | unter 4 GB |
| Systemdatenträger | SSD ab 128 GB | HDD, unter 128 GB oder Typ unbekannt | unter 64 GB |
| Grafik | WDDM 2.0 und DirectX 12 (Feature Level ab 11_0) | ohne Grafiktreiber oder nicht erkennbar | WDDM 1.x oder Feature Level unter 11_0 |
| TPM | 2.0, eingeschaltet | 1.2, oder 2.0 ausgeschaltet | keins (Hinweis auf PTT bzw. fTPM im BIOS) |
| Secure Boot | an, mit den Zertifikaten von 2023 | an, noch mit denen von 2011: weiter mit `1_` bis `3_` | aus oder Legacy-Start |

Die Grafik liest das Skript über `dxdiag` (Treibermodell und Feature Level), ersatzweise aus der
Treiberversion. Hinweise gibt es außerdem zu MBR-Datenträgern (für UEFI vorher mit `MBR2GPT`
umstellen) und zu wenig freiem Platz. Bei einem nicht unterstützten Prozessor oder TPM 1.2 nennt es
den von Microsoft dokumentierten Registry-Wert `AllowUpgradesWithUnsupportedTPMOrCPU`. Jeder Lauf
hängt eine Zeile an `Win11_Uebersicht.csv` an.

Die Prozessorliste ist eine Faustregel nach Namen. Steht ein Prozessor nicht darin, meldet das Skript
gelb und verweist auf Microsofts Liste.

## Hintergrund

### Wie Secure Boot prüft

| Variable | Inhalt | Wer darf sie ändern |
|---|---|---|
| PK (Platform Key) | Schlüssel des Geräteherstellers | nur der Hersteller |
| KEK (Key Exchange Key) | Schlüssel, die db und dbx ändern dürfen, darunter Microsofts KEK | Inhaber des PK |
| db | erlaubte Zertifikate: was damit signiert ist, darf starten | Inhaber eines KEK |
| dbx | Sperrliste: bekannte unsichere Boot-Manager und Zertifikate | Inhaber eines KEK |

### Was abläuft

| Zertifikat von 2011 | läuft ab | Nachfolger von 2023 | Zweck |
|---|---|---|---|
| Microsoft Corporation KEK CA 2011 | Juni 2026 | Microsoft Corporation KEK 2K CA 2023 | signiert Änderungen an db und dbx |
| Microsoft Windows Production PCA 2011 | Oktober 2026 | Windows UEFI CA 2023 | signiert den Windows-Boot-Manager |
| Microsoft Corporation UEFI CA 2011 | Juni 2026 | Microsoft UEFI CA 2023 | signiert Fremd-Bootloader, z.B. Linux |
| (dieselbe UEFI CA 2011) | | Microsoft Option ROM UEFI CA 2023 | signiert Firmware von Steckkarten |

Ein eingerichteter PC startet nach dem Ablaufdatum meist weiter. Problematisch wird alles, was neu
dazukommt: Boot-Manager, Installationsmedien und Sperrlisten, die nur noch mit den 2023-Zertifikaten
signiert sind.

### Was Windows selbst macht

Windows bringt die Zertifikate als signierte Dateien in `C:\Windows\System32\SecureBootUpdates\` mit.
Der Task `Secure-Boot-Update` spielt sie ein, gesteuert über
`HKLM\SYSTEM\CurrentControlSet\Control\Secureboot\AvailableUpdates`:

| Bit | Aufgabe |
|---|---|
| `0x0040` | Windows UEFI CA 2023 in die db |
| `0x0800` | Microsoft UEFI CA 2023 in die db |
| `0x1000` | Option ROM UEFI CA 2023 in die db |
| `0x0004` | KEK 2023 eintragen |
| `0x0100` | Boot-Manager gegen die 2023-Fassung tauschen |
| `0x4000` | Bedingung: Fremd-CAs nur, wenn die UEFI CA 2011 vorhanden ist |

Ein verbleibendes `0x4000` ist kein Fehler. Häufige Gründe, warum es hängt: Microsoft sperrt das
Modell wegen bekannter Firmwarefehler (Ereignis 1802), oder es gibt keine vom Hersteller signierte
KEK-Datei (1803).

| Ereignis (TPM-WMI) | Bedeutung |
|---|---|
| 1808 | alle Zertifikate aktualisiert |
| 1799 | Boot-Manager mit 2023-Signatur installiert |
| 1800, 1801 | Neustart nötig bzw. noch nicht vollständig angewendet |
| 1797 | Boot-Manager-Tausch abgebrochen, Windows UEFI CA 2023 fehlt in der db |
| 1802 | von Microsoft für dieses Modell gesperrt |
| 1803 | keine KEK-Datei des Herstellers |
| 1795, 1796 | Firmware hat das Schreiben abgelehnt |

## Ablage

Alles wird zuerst lokal unter `C:\ProgramData\SecureBootCheck\` gespeichert und dann in denselben
Unterordner neben den Skripten kopiert, z.B. auf den Stick. `<PC>` steht für
`Hostname_Seriennummer`, damit geklonte PCs getrennt bleiben.

| Ordner | Inhalt |
|---|---|
| `Logs\<PC>\` | Protokoll jedes Laufs |
| `Backups\<PC>\` | Sicherung vor jedem Schreiben durch `3_` |
| `Rebuild\<PC>\` | Daten für `4_` zwischen den beiden Läufen |
| `Uebersicht.csv`, `Win11_Uebersicht.csv` | eine Zeile pro Lauf von `1_`/`2_` bzw. `6_` |
| `dbx_KEK2011\` | Sperrlisten mit KEK-2011-Signatur für `3_` |

Diese Ordner sind per `.gitignore` vom Repository ausgeschlossen.

## Getestete Geräte

Stand 18.11.2026.

| Gerät | Ergebnis |
|---|---|
| HP ProDesk 400 G5, HP EliteBook 840 G3 | alles auf 2023, KEK über `4_` |
| Lenovo ThinkCentre M93 und M93p | alles auf 2023, KEK und dbx über `4_` |
| Chromebox Google Teemo (MrChromebox) | alles auf 2023 nur mit `2_`; die Firmware kennt die 2023-Zertifikate ab Werk |
| HP Compaq Pro 6300 | db, Boot-Manager und dbx auf 2023, der KEK fehlt. `4_` geht hier nicht (siehe oben). Die Sperrliste von Windows ist nur mit dem KEK 2023 signiert; `3_` nimmt deshalb die KEK-2011-Fassung. |
| 10ZiG Thin Client | kein Secure Boot, nicht betroffen |

## Aufruf per PowerShell

```powershell
powershell -ExecutionPolicy Bypass -File .\SecureBootCheck.ps1                # 1_
powershell -ExecutionPolicy Bypass -File .\SecureBootCheck.ps1 -Apply -Force  # 2_
powershell -ExecutionPolicy Bypass -File .\SecureBootManual.ps1               # nur den Plan von 3_ zeigen
powershell -ExecutionPolicy Bypass -File .\SecureBootManual.ps1 -Execute      # 3_
powershell -ExecutionPolicy Bypass -File .\SecureBootRebuild.ps1              # 4_
powershell -ExecutionPolicy Bypass -File .\SecureBootRebuild.ps1 -Restore     # 5_
powershell -ExecutionPolicy Bypass -File .\Win11Check.ps1                     # 6_
```

| Parameter | Skripte | Wirkung |
|---|---|---|
| `-NoPause` | alle | am Ende nicht auf Enter warten |
| `-PayloadDir` | Manual, Rebuild | anderer Ordner mit Update-Dateien statt `SecureBootUpdates` |
| `-Kek2011Dir` | Manual | anderer Ordner statt `dbx_KEK2011` |
| `-StateDir` | Rebuild | Rebuild-Daten von einem anderen Ort lesen, z.B. vom Stick |

Gemeinsame Funktionen liegen in `SecureBootCommon.ps1`, das alle Skripte laden.

## Selbsttest

`tests\Tests_ausfuehren.cmd` prüft ohne Administratorrechte und ohne die Firmware anzufassen: Syntax,
ASCII und Zeilenenden aller Skripte, die Starter, die Parser- und Entscheidungsfunktionen mit
künstlichen Daten und die Windows-11-Bewertungen mit Beispielprozessoren. `tests\Testdateien_sammeln.cmd`
kopiert die Update-Dateien und Variablen dieses PCs nach `tests\fixtures\`; liegen sie vor, prüft der
Test zusätzlich jede echte Microsoft-Datei und die Dateien in `dbx_KEK2011`. Nach einem Windows-Update
mit neuen Dateien lohnt sich das vor dem nächsten Schreiben.

## Haftung

Eingriffe in die Secure-Boot-Variablen können einen PC am Starten hindern. Die Benutzung erfolgt auf
eigene Gefahr. Vor dem ersten Schreiben die Ausgabe von `1_Pruefen.cmd` lesen und den Notfallweg
kennen.
