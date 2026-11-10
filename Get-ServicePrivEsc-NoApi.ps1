#Requires -Version 3.0
<#
.SYNOPSIS
    Dienst-PrivEsc-Audit OHNE WinAPI/P-Invoke.

    Ermittelt Start-/Stopp-/ChangeConfig-Rechte des aktuellen Benutzers
    über den Security-Descriptor jedes Dienstes (sc.exe sdshow) und listet
    Dienste mit "unquoted service path" (inkl. beschreibbarer
    Hijack-Verzeichnisse).

.DESCRIPTION
    Kein Add-Type/P-Invoke. Der SDDL-String aus `sc.exe sdshow` wird mit
    [Security.AccessControl.RawSecurityDescriptor] (reines .NET) geparst –
    das löst auch die SDDL-Kurzaliase (WD, AU, BU, SY, ...) automatisch in
    SIDs auf. Anschließend wird die DACL gegen die SIDs des aktuellen
    Tokens ausgewertet.

    Hinweis / Grenzen gegenüber der OpenService()-Variante:
    - Es wird ein vereinfachter Access-Check nachgebildet:
        effektiv = (Summe passender Allow-ACEs) AND NOT (passende Deny-ACEs)
    - UAC "deny-only"-SIDs im gefilterten Token werden nicht als solche
      erkannt -> Rechte können leicht ÜBERschätzt werden. Für ein exakt
      token-genaues Ergebnis die OpenService()-Variante nutzen.
    - Generische Rechte (GA/GE/GW) werden über die Service-Generic-Mapping
      aufgelöst.

.NOTES
    Für PrivEsc-Bewertung NICHT elevated ausführen.
    Optional: -Csv <Pfad> exportiert beide Tabellen als CSV.
#>
[CmdletBinding()]
param(
    [string]$Csv
)

# --- Service-Zugriffsrechte & Generic-Mapping ---------------------------
$SERVICE_CHANGE_CONFIG = 0x0002
$SERVICE_START         = 0x0010
$SERVICE_STOP          = 0x0020
$SERVICE_ALL_ACCESS    = 0xF01FF

function Expand-Mask {
    param([uint32]$m)
    if ($m -band 0x10000000) { $m = $m -bor $SERVICE_ALL_ACCESS }                 # GENERIC_ALL
    if ($m -band 0x20000000) { $m = $m -bor ($SERVICE_START -bor $SERVICE_STOP -bor 0x40 -bor 0x100) } # GENERIC_EXECUTE
    if ($m -band 0x40000000) { $m = $m -bor $SERVICE_CHANGE_CONFIG }              # GENERIC_WRITE
    return [uint32]$m
}

function Test-Writable {
    param([string]$Dir)
    if (-not (Test-Path -LiteralPath $Dir)) { return $false }
    $probe = Join-Path $Dir ("_w_{0}.tmp" -f ([guid]::NewGuid().ToString('N')))
    try {
        [IO.File]::WriteAllText($probe, 'x')
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        return $true
    } catch { return $false }
}

# --- Token-SIDs des aktuellen Benutzers ---------------------------------
$ident = [Security.Principal.WindowsIdentity]::GetCurrent()
$mySids = New-Object 'System.Collections.Generic.HashSet[string]'
[void]$mySids.Add($ident.User.Value)
foreach ($g in $ident.Groups) { [void]$mySids.Add($g.Value) }

$elevated = ([Security.Principal.WindowsPrincipal]$ident).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Kontext : $($ident.Name)" -ForegroundColor Cyan
Write-Host "Elevated: $elevated   (SDDL-basiert, ohne WinAPI)`n" -ForegroundColor Cyan

$services = Get-CimInstance Win32_Service

# --- 1) Rechte per sc.exe sdshow auswerten ------------------------------
$perm = foreach ($s in $services) {

    $raw = & sc.exe sdshow $s.Name 2>$null
    $sddl = (($raw) -join '').Trim()
    if ($sddl -notmatch 'D:') { continue }          # kein/keine lesbare DACL -> überspringen

    try   { $sd = New-Object Security.AccessControl.RawSecurityDescriptor($sddl) }
    catch { continue }
    if ($null -eq $sd.DiscretionaryAcl) { continue }

    $allow = [uint32]0
    $deny  = [uint32]0
    foreach ($ace in $sd.DiscretionaryAcl) {
        $sid = $null
        try { $sid = $ace.SecurityIdentifier.Value } catch { continue }
        if (-not $mySids.Contains($sid)) { continue }
        $m = Expand-Mask ([uint32]$ace.AccessMask)
        switch ($ace.AceQualifier) {
            'AccessAllowed' { $allow = $allow -bor $m }
            'AccessDenied'  { $deny  = $deny  -bor $m }
        }
    }
    $eff = $allow -band (-bnot $deny)

    $canStart  = [bool]($eff -band $SERVICE_START)
    $canStop   = [bool]($eff -band $SERVICE_STOP)
    $canChange = [bool]($eff -band $SERVICE_CHANGE_CONFIG)

    if ($canStart -or $canStop -or $canChange) {
        [pscustomobject]@{
            Name         = $s.Name
            State        = $s.State
            StartMode    = $s.StartMode
            CanStart     = $canStart
            CanStop      = $canStop
            CanChangeCfg = $canChange
            RunAs        = $s.StartName
        }
    }
}

# --- 2) Unquoted Service Paths (ohnehin ohne WinAPI) --------------------
$unquoted = foreach ($s in $services) {
    $path = $s.PathName
    if ([string]::IsNullOrWhiteSpace($path)) { continue }
    $p = $path.Trim()
    if ($p.StartsWith('"')) { continue }

    if ($p -match '(?i)^(?<exe>.*?\.exe)') { $exe = $matches['exe'] }
    else                                   { $exe = ($p -split '\s', 2)[0] }
    if ($exe -notmatch '\s') { continue }

    $writable = @()
    $parts = $exe -split ' '
    $acc = ''
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        $acc = if ($i -eq 0) { $parts[0] } else { "$acc $($parts[$i])" }
        $dir = Split-Path -Path $acc -Parent
        if ($dir -and (Test-Writable $dir)) { $writable += $dir }
    }

    [pscustomobject]@{
        Name           = $s.Name
        State          = $s.State
        StartMode      = $s.StartMode
        PathName       = $path
        RunAs          = $s.StartName
        WritableHijack = ($writable -join '; ')
    }
}

# --- Ausgabe -------------------------------------------------------------
Write-Host "=== Dienste mit Start/Stopp/ChangeConfig-Rechten ($(@($perm).Count)) ===" -ForegroundColor Yellow
$perm | Sort-Object Name | Format-Table -AutoSize

Write-Host "=== Unquoted Service Paths ($(@($unquoted).Count)) ===" -ForegroundColor Yellow
Write-Host "(WritableHijack = Verzeichnis beschreibbar => real ausnutzbar)" -ForegroundColor DarkGray
$unquoted | Sort-Object Name | Format-Table -AutoSize -Wrap

if ($Csv) {
    $base = [IO.Path]::Combine(
        (Split-Path -Path $Csv -Parent),
        [IO.Path]::GetFileNameWithoutExtension($Csv))
    $perm     | Sort-Object Name | Export-Csv -NoTypeInformation -Encoding UTF8 "$base`_permissions.csv"
    $unquoted | Sort-Object Name | Export-Csv -NoTypeInformation -Encoding UTF8 "$base`_unquoted.csv"
    Write-Host "CSV geschrieben: $base`_permissions.csv / $base`_unquoted.csv" -ForegroundColor Green
}
