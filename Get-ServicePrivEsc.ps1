#Requires -Version 3.0
<#
.SYNOPSIS
    Dienst-PrivEsc-Audit: listet Dienste, die der aktuelle Benutzer
    starten, stoppen oder umkonfigurieren darf, sowie Dienste mit
    "unquoted service path" (inkl. Prüfung auf beschreibbare
    Hijack-Verzeichnisse).

.DESCRIPTION
    Die Rechte werden per echtem Zugriffscheck ermittelt: OpenService()
    wird mit den jeweiligen Access-Masken aufgerufen. Gelingt das Öffnen
    des Handles, besitzt der aufrufende Token das Recht. Es wird dabei
    KEIN Dienst gestartet, gestoppt oder geändert.

    SERVICE_CHANGE_CONFIG ist oft der direktere PrivEsc-Vektor: wer die
    Konfiguration ändern darf, kann binPath auf eine eigene Binärdatei
    umbiegen und (sofern auch Start/Stopp erlaubt bzw. Dienst neustartet)
    Code im Dienstkontext ausführen.

.NOTES
    Für eine PrivEsc-Bewertung NICHT als Admin ausführen – der
    UAC-gefilterte Standard-Token zeigt, was der normale Benutzer darf.

    Optional: -Csv <Pfad> exportiert beide Tabellen als CSV.
#>
[CmdletBinding()]
param(
    [string]$Csv
)

Add-Type -ErrorAction Stop @"
using System;
using System.Runtime.InteropServices;

public static class Svc {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenSCManager(string machine, string database, uint access);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenService(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool CloseServiceHandle(IntPtr handle);

    public const uint SC_MANAGER_CONNECT   = 0x0001;
    public const uint SERVICE_START         = 0x0010;
    public const uint SERVICE_STOP          = 0x0020;
    public const uint SERVICE_CHANGE_CONFIG = 0x0002;

    public static bool HasAccess(IntPtr scm, string name, uint access) {
        IntPtr h = OpenService(scm, name, access);
        if (h != IntPtr.Zero) { CloseServiceHandle(h); return true; }
        return false;
    }
}
"@

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

# --- Setup ---------------------------------------------------------------
$scm = [Svc]::OpenSCManager($null, $null, [Svc]::SC_MANAGER_CONNECT)
if ($scm -eq [IntPtr]::Zero) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "OpenSCManager fehlgeschlagen: $(([ComponentModel.Win32Exception]$err).Message)"
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$id).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Kontext : $($id.Name)" -ForegroundColor Cyan
Write-Host "Elevated: $elevated`n" -ForegroundColor Cyan

$services = Get-CimInstance Win32_Service

# --- 1) Start / Stopp / ChangeConfig-Berechtigungen ----------------------
$perm = foreach ($s in $services) {
    $canStart  = [Svc]::HasAccess($scm, $s.Name, [Svc]::SERVICE_START)
    $canStop   = [Svc]::HasAccess($scm, $s.Name, [Svc]::SERVICE_STOP)
    $canChange = [Svc]::HasAccess($scm, $s.Name, [Svc]::SERVICE_CHANGE_CONFIG)
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

# --- 2) Unquoted Service Paths ------------------------------------------
$unquoted = foreach ($s in $services) {
    $path = $s.PathName
    if ([string]::IsNullOrWhiteSpace($path)) { continue }
    $p = $path.Trim()
    if ($p.StartsWith('"')) { continue }                    # korrekt zitiert -> ok

    if ($p -match '(?i)^(?<exe>.*?\.exe)') { $exe = $matches['exe'] }
    else                                   { $exe = ($p -split '\s', 2)[0] }

    if ($exe -notmatch '\s') { continue }                   # kein Leerzeichen im Pfad -> ok

    # Beschreibbare Hijack-Verzeichnisse ermitteln
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

[Svc]::CloseServiceHandle($scm) | Out-Null

# --- Ausgabe -------------------------------------------------------------
Write-Host "=== Dienste mit Start/Stopp/ChangeConfig-Rechten ($(@($perm).Count)) ===" -ForegroundColor Yellow
$perm | Sort-Object Name | Format-Table -AutoSize

Write-Host "=== Unquoted Service Paths ($(@($unquoted).Count)) ===" -ForegroundColor Yellow
Write-Host "(WritableHijack = Verzeichnis beschreibbar => real ausnutzbar)" -ForegroundColor DarkGray
$unquoted | Sort-Object Name | Format-Table -AutoSize -Wrap

# --- Optionaler CSV-Export ----------------------------------------------
if ($Csv) {
    $base = [IO.Path]::Combine(
        (Split-Path -Path $Csv -Parent),
        [IO.Path]::GetFileNameWithoutExtension($Csv))
    $perm     | Sort-Object Name | Export-Csv -NoTypeInformation -Encoding UTF8 "$base`_permissions.csv"
    $unquoted | Sort-Object Name | Export-Csv -NoTypeInformation -Encoding UTF8 "$base`_unquoted.csv"
    Write-Host "CSV geschrieben: $base`_permissions.csv / $base`_unquoted.csv" -ForegroundColor Green
}
