#Requires -Version 5.1
<#
.SYNOPSIS
  GIS EPD Slot Grabber — PowerShell version
  Читает куки Яндекс Браузера, бронирует слоты в ГИС ЭПД.

.NOTES
  Запускать через Task Scheduler от имени текущего пользователя.
  PowerShell встроен в Windows — установка не нужна.
#>

param(
    [string]$TelegramToken = $env:GIS_TG_TOKEN,
    [string]$TelegramChat  = $env:GIS_TG_CHAT
)

$PORTAL   = "https://eopp.epd-portal.ru"
$LOG_DIR  = Join-Path $env:APPDATA "GisEpdGrabber"
$LOG_FILE = Join-Path $LOG_DIR "grabber.log"

if (-not (Test-Path $LOG_DIR)) { New-Item -ItemType Directory -Path $LOG_DIR | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $ts  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts $Level : $Msg"
    Write-Host $line
    Add-Content -Path $LOG_FILE -Value $line -Encoding UTF8
}

function Send-Telegram {
    param([string]$Text)
    if (-not $TelegramToken -or -not $TelegramChat) {
        Write-Log "Telegram не настроен (GIS_TG_TOKEN / GIS_TG_CHAT)" "WARN"
        return
    }
    try {
        $body = @{ chat_id = $TelegramChat; text = $Text } | ConvertTo-Json
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$TelegramToken/sendMessage" `
            -Method Post -Body $body -ContentType "application/json; charset=utf-8" `
            -TimeoutSec 10 | Out-Null
    } catch {
        Write-Log "TG error: $_" "WARN"
    }
}

# ──────────────────────────────────────────────
# Cookie extraction (Yandex Browser / Edge / Chrome)
# ──────────────────────────────────────────────

function Get-DecryptionKey {
    param([string]$LocalStatePath)
    if (-not (Test-Path $LocalStatePath)) { return $null }
    try {
        $state   = Get-Content $LocalStatePath -Raw | ConvertFrom-Json
        $keyB64  = $state.os_crypt.encrypted_key
        if (-not $keyB64) { return $null }
        $keyEnc  = [System.Convert]::FromBase64String($keyB64)
        # Remove DPAPI prefix (first 5 bytes = "DPAPI")
        $keyEnc  = $keyEnc[5..($keyEnc.Length - 1)]
        $plain   = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $keyEnc, $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return $plain
    } catch {
        Write-Log "Key extract error: $_" "DEBUG"
        return $null
    }
}

function Decrypt-CookieValue {
    param([byte[]]$Encrypted, [byte[]]$Key)
    if (-not $Encrypted -or $Encrypted.Length -eq 0) { return "" }

    # v10/v11 = Chrome v80+ AES-256-GCM
    $prefix = [System.Text.Encoding]::ASCII.GetString($Encrypted[0..2])
    if ($prefix -eq "v10" -or $prefix -eq "v11") {
        if (-not $Key) { return "" }
        try {
            $nonce      = $Encrypted[3..14]
            $ciphertext = $Encrypted[15..($Encrypted.Length - 1)]

            # AesGcm available in .NET Core 3+ / .NET 5+
            # Windows PowerShell 5.1 uses .NET Framework 4.x — no AesGcm
            # Try via .NET Runtime interop (PowerShell 7+) first
            if ([System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription -match "Core|\.NET 5|\.NET 6|\.NET 7|\.NET 8") {
                Add-Type -AssemblyName System.Security.Cryptography.Algorithms -ErrorAction SilentlyContinue
                $aes  = [System.Security.Cryptography.AesGcm]::new([byte[]]$Key)
                $tag  = $ciphertext[($ciphertext.Length - 16)..($ciphertext.Length - 1)]
                $ct   = $ciphertext[0..($ciphertext.Length - 17)]
                $plain = New-Object byte[] $ct.Length
                $aes.Decrypt($nonce, $ct, $tag, $plain)
                $aes.Dispose()
                return [System.Text.Encoding]::UTF8.GetString($plain)
            } else {
                # Fallback: use Python if available
                $pyCmd = "python -c `"import sys,base64,json; from cryptography.hazmat.primitives.ciphers.aead import AESGCM; key=base64.b64decode(sys.argv[1]); enc=base64.b64decode(sys.argv[2]); print(AESGCM(key).decrypt(enc[3:15],enc[15:],None).decode())`" " +
                          [Convert]::ToBase64String($Key) + " " + [Convert]::ToBase64String($Encrypted)
                $result = & cmd /c $pyCmd 2>$null
                return if ($result) { $result.Trim() } else { "" }
            }
        } catch {
            Write-Log "AES decrypt error: $_" "DEBUG"
            return ""
        }
    }

    # DPAPI fallback (old Chrome / some profiles)
    try {
        $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $Encrypted, $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [System.Text.Encoding]::UTF8.GetString($plain)
    } catch {
        return ""
    }
}

function Get-BrowserCookies {
    param([string]$Domain = "eopp.epd-portal.ru")

    $localApp = $env:LOCALAPPDATA
    $browsers = @(
        @{
            Name      = "Yandex Browser"
            CookieDB  = "$localApp\Yandex\YandexBrowser\User Data\Default\Network\Cookies"
            CookieDB2 = "$localApp\Yandex\YandexBrowser\User Data\Default\Cookies"
            LocalState = "$localApp\Yandex\YandexBrowser\User Data\Local State"
        },
        @{
            Name      = "Microsoft Edge"
            CookieDB  = "$localApp\Microsoft\Edge\User Data\Default\Network\Cookies"
            CookieDB2 = "$localApp\Microsoft\Edge\User Data\Default\Cookies"
            LocalState = "$localApp\Microsoft\Edge\User Data\Local State"
        },
        @{
            Name      = "Google Chrome"
            CookieDB  = "$localApp\Google\Chrome\User Data\Default\Network\Cookies"
            CookieDB2 = "$localApp\Google\Chrome\User Data\Default\Cookies"
            LocalState = "$localApp\Google\Chrome\User Data\Local State"
        }
    )

    foreach ($browser in $browsers) {
        $dbPath = if (Test-Path $browser.CookieDB) { $browser.CookieDB }
                  elseif (Test-Path $browser.CookieDB2) { $browser.CookieDB2 }
                  else { continue }

        Write-Log "Reading cookies from $($browser.Name): $dbPath"

        $key    = Get-DecryptionKey -LocalStatePath $browser.LocalState
        $tmpDb  = [System.IO.Path]::GetTempFileName() + ".db"

        try {
            Copy-Item $dbPath $tmpDb -Force

            # Use System.Data.SQLite if available, otherwise try sqlite3.exe
            $cookies = @{}

            # Try loading SQLite via .NET
            $sqliteDll = "$PSScriptRoot\System.Data.SQLite.dll"
            if (-not (Test-Path $sqliteDll)) {
                # Try to find sqlite3.exe
                $sqlite3 = Get-Command sqlite3.exe -ErrorAction SilentlyContinue
                if ($sqlite3) {
                    $rows = & sqlite3.exe $tmpDb "SELECT name, encrypted_value, value FROM cookies WHERE host_key LIKE '%$Domain%'" 2>$null
                    foreach ($row in $rows) {
                        $parts = $row -split '\|'
                        if ($parts.Count -ge 1) {
                            $name  = $parts[0]
                            $plain = if ($parts.Count -ge 3) { $parts[2] } else { "" }
                            if ($name -and $plain) { $cookies[$name] = $plain }
                        }
                    }
                } else {
                    # Fallback: try Python's sqlite3
                    $pyScript = @"
import sqlite3, json, sys
db = sys.argv[1]
domain = sys.argv[2]
conn = sqlite3.connect(db)
rows = conn.execute("SELECT name, encrypted_value, value FROM cookies WHERE host_key LIKE '%' || ? || '%'", (domain,)).fetchall()
result = {}
for name, enc, val in rows:
    if val: result[name] = val
print(json.dumps(result))
conn.close()
"@
                    $tmpPy = [System.IO.Path]::GetTempFileName() + ".py"
                    $pyScript | Set-Content $tmpPy -Encoding UTF8
                    $out = & python $tmpPy $tmpDb $Domain 2>$null
                    if ($out) {
                        $parsed = $out | ConvertFrom-Json
                        $parsed.PSObject.Properties | ForEach-Object { $cookies[$_.Name] = $_.Value }
                    }
                    Remove-Item $tmpPy -Force -ErrorAction SilentlyContinue
                }
            }

            if ($cookies.Count -gt 0) {
                Write-Log "Found $($cookies.Count) cookies: $(($cookies.Keys | Select-Object -First 6) -join ', ')"
                return $cookies
            }
        } catch {
            Write-Log "Cookie read error: $_" "WARN"
        } finally {
            Remove-Item $tmpDb -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Log "No browser cookies found!" "ERROR"
    return @{}
}

# ──────────────────────────────────────────────
# Portal API calls
# ──────────────────────────────────────────────

function Invoke-PortalApi {
    param(
        [string]$Method,
        [string]$Path,
        [hashtable]$Cookies,
        [object]$Body = $null
    )

    $cookieStr = ($Cookies.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "

    $headers = @{
        "User-Agent"   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
        "Accept"       = "application/json, text/plain, */*"
        "Content-Type" = "application/json"
        "Cookie"       = $cookieStr
        "Origin"       = $PORTAL
        "Referer"      = "$PORTAL/ru/reservations"
    }

    $params = @{
        Uri             = "$PORTAL$Path"
        Method          = $Method
        Headers         = $headers
        TimeoutSec      = 20
        UseBasicParsing = $true
        ErrorAction     = "Stop"
    }

    if ($Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 10)
    }

    $resp = Invoke-WebRequest @params
    return @{ Status = [int]$resp.StatusCode; Content = $resp.Content }
}

function Check-Session {
    param([hashtable]$Cookies)
    try {
        $r = Invoke-PortalApi -Method GET -Path "/auth/Account/GetCurrentUser?isTso=false" -Cookies $Cookies
        if ($r.Status -eq 200) {
            $user = $r.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
            return $user
        }
        Write-Log "GetCurrentUser → $($r.Status)" "WARN"
        return $null
    } catch {
        if ($_ -match "401") { return $null }
        Write-Log "Session check error: $_" "ERROR"
        return $null
    }
}

function Search-Reservations {
    param([hashtable]$Cookies)
    try {
        $body = @{ commonParams = @{ pageIndex = 0; pageSize = 20 }; filters = @{} }
        $r    = Invoke-PortalApi -Method POST -Path "/reservations-api/v1/Search" -Cookies $Cookies -Body $body
        if ($r.Status -eq 200) {
            $data  = $r.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
            $items = if ($data.items) { $data.items } elseif ($data -is [array]) { $data } else { @() }
            return $items
        }
        if ($r.Status -eq 401) { return $null }
        Write-Log "Search → $($r.Status)" "ERROR"
        return @()
    } catch {
        if ($_ -match "401") { return $null }
        Write-Log "Search error: $_" "ERROR"
        return @()
    }
}

function Reserve-Checkpoint {
    param([string]$ReservationId, [hashtable]$Cookies)
    try {
        $r = Invoke-PortalApi -Method POST -Path "/reservations-api/v1/ReserveCheckpoint?reservationId=$ReservationId" `
                              -Cookies $Cookies -Body @{}
        if ($r.Status -in 200, 201, 204) {
            return @{ Success = $true }
        }
        if ($r.Status -eq 401) { return @{ Success = $false; Expired = $true } }

        $err = $r.Content
        if ($err -match "41102") { return @{ Success = $false; Error = "Все слоты заняты (41102)" } }
        if ($err -match "41104") { return @{ Success = $false; Error = "Слоты не найдены (41104)" } }
        return @{ Success = $false; Error = "HTTP $($r.Status): $($err.Substring(0, [Math]::Min(80, $err.Length)))" }
    } catch {
        if ($_ -match "401") { return @{ Success = $false; Expired = $true } }
        return @{ Success = $false; Error = $_.ToString() }
    }
}

# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

$now = Get-Date -Format "yyyy-MM-dd HH:mm"
Write-Log "=== GIS EPD Slot Grabber started at $now ==="

# 1. Get cookies
$cookies = Get-BrowserCookies -Domain "eopp.epd-portal.ru"
if ($cookies.Count -eq 0) {
    $msg = "[$now] Куки не найдены. Войдите в eopp.epd-portal.ru через Яндекс Браузер."
    Write-Log $msg "ERROR"
    Send-Telegram "⚠️ ГИС ЭПД: $msg"
    exit 1
}

# 2. Check session
$user = Check-Session -Cookies $cookies
if (-not $user) {
    $msg = "[$now] Сессия истекла. Войдите в eopp.epd-portal.ru заново."
    Write-Log $msg "ERROR"
    Send-Telegram "⚠️ ГИС ЭПД: $msg"
    exit 1
}

$name = if ($user.fullName) { $user.fullName } elseif ($user.login) { $user.login } else { "пользователь" }
Write-Log "Session OK: $name"

# 3. Get reservations
$reservations = Search-Reservations -Cookies $cookies
if ($null -eq $reservations) {
    $msg = "[$now] Сессия истекла при поиске заявок."
    Write-Log $msg "ERROR"
    Send-Telegram "⚠️ ГИС ЭПД: $msg"
    exit 1
}

Write-Log "Found $($reservations.Count) reservation(s)"
if ($reservations.Count -eq 0) {
    Write-Log "No active reservations — nothing to book"
    exit 0
}

# 4. Book slots
$booked = @()
$errors = @()

foreach ($item in $reservations) {
    $resId = if ($item.id) { $item.id }
             elseif ($item.reservationRequestId) { $item.reservationRequestId }
             elseif ($item.reservationId) { $item.reservationId }
             else { "" }

    if (-not $resId) {
        Write-Log "Reservation missing ID, skipping" "WARN"
        continue
    }

    Write-Log "Booking reservation $resId (status=$($item.status))..."
    $result = Reserve-Checkpoint -ReservationId $resId -Cookies $cookies

    if ($result.Success) {
        $booked += $resId
        Write-Log "✓ Slot booked for $resId"
    } elseif ($result.Expired) {
        $msg = "[$now] Сессия истекла при бронировании. Войдите в портал заново."
        Write-Log $msg "ERROR"
        Send-Telegram "⚠️ ГИС ЭПД: $msg"
        exit 1
    } else {
        $err = $result.Error
        $errors += "$resId : $err"
        Write-Log "✗ $resId : $err" "WARN"
    }
}

# 5. Report
if ($booked.Count -gt 0) {
    $msg = "✅ ГИС ЭПД [$now]: забронировано $($booked.Count) слот(ов).`nЗаявки: $($booked -join ', ')"
    Write-Log $msg
    Send-Telegram $msg
} elseif ($errors.Count -gt 0) {
    $msg = "❌ ГИС ЭПД [$now]: не удалось забронировать.`n$($errors -join "`n")"
    Write-Log $msg "ERROR"
    Send-Telegram $msg
} else {
    Write-Log "No bookable reservations found"
}

Write-Log "=== Done ==="
