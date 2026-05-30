"""
GIS EPD Slot Grabber — Windows standalone
Читает куки из браузера на Windows, бронирует слот в ГИС ЭПД.

Поддерживаемые браузеры (в порядке приоритета):
  1. Яндекс Браузер
  2. Microsoft Edge
  3. Google Chrome

Запускать через Task Scheduler в 10:00 и 12:00 МСК.
"""
import sys
import os
import json
import sqlite3
import shutil
import tempfile
import logging
import base64
import struct
from pathlib import Path
from datetime import datetime

import httpx

# ---------- Logging ----------
LOG_DIR = Path(os.environ.get("APPDATA", ".")) / "GisEpdGrabber"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "grabber.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ---------- Config ----------
PORTAL = "https://eopp.epd-portal.ru"
TELEGRAM_TOKEN = os.environ.get("GIS_TG_TOKEN", "")   # заполнить или задать переменную среды
TELEGRAM_CHAT = os.environ.get("GIS_TG_CHAT", "")     # chat_id Анастасии

# ---------- Telegram ----------
def send_tg(text: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        log.warning("TG not configured (GIS_TG_TOKEN / GIS_TG_CHAT not set)")
        return
    try:
        r = httpx.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT, "text": text},
            timeout=10,
        )
        if r.status_code != 200:
            log.warning(f"TG send failed: {r.status_code} {r.text[:100]}")
    except Exception as e:
        log.error(f"TG error: {e}")

# ---------- Cookie extraction ----------
def _get_yandex_path() -> Path | None:
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    candidates = [
        local / "Yandex" / "YandexBrowser" / "User Data" / "Default" / "Network" / "Cookies",
        local / "Yandex" / "YandexBrowser" / "User Data" / "Default" / "Cookies",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None

def _get_edge_path() -> Path | None:
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    p = local / "Microsoft" / "Edge" / "User Data" / "Default" / "Network" / "Cookies"
    if not p.exists():
        p = local / "Microsoft" / "Edge" / "User Data" / "Default" / "Cookies"
    return p if p.exists() else None

def _get_chrome_path() -> Path | None:
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    p = local / "Google" / "Chrome" / "User Data" / "Default" / "Network" / "Cookies"
    if not p.exists():
        p = local / "Google" / "Chrome" / "User Data" / "Default" / "Cookies"
    return p if p.exists() else None

def _get_decryption_key(local_state_dir: Path) -> bytes | None:
    """Extract AES key from Local State (Chrome v80+ encryption)."""
    ls = local_state_dir / "Local State"
    log.info(f"Local State: {ls} exists={ls.exists()}")
    if not ls.exists():
        return None
    try:
        state = json.loads(ls.read_text(encoding="utf-8"))
        key_b64 = state.get("os_crypt", {}).get("encrypted_key")
        if not key_b64:
            log.warning("os_crypt.encrypted_key not found in Local State")
            return None
        key_encrypted = base64.b64decode(key_b64)
        # First 5 bytes are 'DPAPI' prefix
        key_encrypted = key_encrypted[5:]
        # Decrypt with DPAPI
        import ctypes
        import ctypes.wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        p = ctypes.create_string_buffer(key_encrypted)
        blobin = DATA_BLOB(ctypes.sizeof(p), p)
        blobout = DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout)
        )
        if not ok or blobout.cbData == 0:
            log.warning(f"CryptUnprotectData failed for AES key (ok={ok} cbData={blobout.cbData})")
            return None
        ptr = ctypes.string_at(blobout.pbData, blobout.cbData)
        ctypes.windll.kernel32.LocalFree(blobout.pbData)
        log.info(f"AES master key extracted OK: {len(ptr)} bytes")
        return ptr
    except Exception as e:
        log.warning(f"Key extraction error: {e}")
        return None

def _decrypt_cookie_value(encrypted: bytes, key: bytes | None, name: str = "") -> str:
    """Decrypt a cookie value (v10/v11 AES-GCM or DPAPI fallback)."""
    if not encrypted:
        return ""

    prefix = encrypted[:3]
    # v10/v11 prefix = Chrome v80+ AES-256-GCM
    if prefix in (b"v10", b"v11"):
        if not key:
            log.info(f"Cookie '{name}': v10/v11 prefix but no AES key")
            return ""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = encrypted[3:15]
            ciphertext = encrypted[15:]
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
            try:
                val = plaintext.decode("utf-8")
                if '�' in val:
                    log.warning(f"Cookie '{name}': AES-GCM ok but value has replacement chars (bad key?)")
                    return ""
                return val
            except UnicodeDecodeError:
                log.warning(f"Cookie '{name}': AES-GCM ok but UTF-8 decode failed len={len(plaintext)}")
                return ""
        except Exception as e:
            log.info(f"Cookie '{name}': AES decrypt error: {e}")
            return ""

    # Unknown prefix — log for diagnostics
    log.info(f"Cookie '{name}': unknown prefix {encrypted[:4]!r} len={len(encrypted)}, trying DPAPI")

    # DPAPI fallback (old Chrome / some profiles)
    try:
        import ctypes
        import ctypes.wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        p = ctypes.create_string_buffer(encrypted)
        blobin = DATA_BLOB(ctypes.sizeof(p), p)
        blobout = DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout)
        )
        if not ok or blobout.cbData == 0:
            log.info(f"Cookie '{name}': DPAPI failed (ok={ok} cbData={blobout.cbData})")
            return ""
        result = ctypes.string_at(blobout.pbData, blobout.cbData)
        ctypes.windll.kernel32.LocalFree(blobout.pbData)
        try:
            val = result.decode("utf-8")
            if '�' in val:
                log.warning(f"Cookie '{name}': DPAPI produced replacement chars (not DPAPI data?)")
                return ""
            return val
        except UnicodeDecodeError:
            log.warning(f"Cookie '{name}': DPAPI ok but UTF-8 decode failed len={len(result)}")
            return ""
    except Exception as e:
        log.debug(f"DPAPI decrypt error: {e}")
        return ""

def _win_copy_locked(src: Path, dst: Path) -> bool:
    """Copy a file locked by a browser using Win32 sharing flags (64-bit safe)."""
    try:
        import ctypes
        import ctypes.wintypes
        k32 = ctypes.windll.kernel32
        GENERIC_READ   = 0x80000000
        FILE_SHARE_READ  = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        FILE_SHARE_ALL = 0x00000007
        OPEN_EXISTING  = 3
        INVALID_HANDLE = ctypes.c_void_p(-1).value
        k32.CreateFileW.restype = ctypes.wintypes.HANDLE
        # First try with FILE_SHARE_READ|WRITE (Chrome standard), then full ALL
        for share_flags in (FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SHARE_ALL):
            handle = k32.CreateFileW(str(src), GENERIC_READ, share_flags, None, OPEN_EXISTING, 0, None)
            if handle is not None and handle != INVALID_HANDLE:
                break
            log.info(f"_win_copy_locked: share=0x{share_flags:x} err={k32.GetLastError()} file={src.name}")
        else:
            log.warning(f"_win_copy_locked: all share modes failed err={k32.GetLastError()} for {src.name}")
            return False
        try:
            size_hi = ctypes.wintypes.DWORD(0)
            k32.GetFileSize.restype = ctypes.wintypes.DWORD
            size_lo = k32.GetFileSize(handle, ctypes.byref(size_hi))
            size = (size_hi.value << 32) | size_lo
            if size == 0:
                log.warning(f"_win_copy_locked: file size=0 for {src.name}")
                return False
            buf = ctypes.create_string_buffer(size)
            read = ctypes.wintypes.DWORD(0)
            ok = k32.ReadFile(handle, buf, size, ctypes.byref(read), None)
            log.info(f"_win_copy_locked: ReadFile ok={ok} read={read.value} size={size} file={src.name}")
            dst.write_bytes(buf.raw[: read.value])
            return read.value > 0
        finally:
            k32.CloseHandle(handle)
    except Exception as e:
        log.warning(f"_win_copy_locked failed: {e}")
        return False


def get_cookies_for_domain(domain: str = ".eopp.epd-portal.ru") -> dict:
    """
    Read cookies for given domain from the first available browser.
    Returns dict {name: value}.
    """
    # Find browser cookie file and local state dir
    paths = [
        (_get_yandex_path(), Path(os.environ.get("LOCALAPPDATA","")) / "Yandex" / "YandexBrowser" / "User Data"),
        (_get_edge_path(),   Path(os.environ.get("LOCALAPPDATA","")) / "Microsoft" / "Edge" / "User Data"),
        (_get_chrome_path(), Path(os.environ.get("LOCALAPPDATA","")) / "Google" / "Chrome" / "User Data"),
    ]

    for cookie_file, ls_dir in paths:
        if not cookie_file:
            continue
        log.info(f"Reading cookies from: {cookie_file}")

        key = _get_decryption_key(ls_dir)

        # Copy to temp (browser locks the file while open — use Win32 sharing flags)
        tmp = Path(tempfile.mktemp(suffix=".db"))
        try:
            if not _win_copy_locked(cookie_file, tmp):
                shutil.copy2(cookie_file, tmp)
            conn = sqlite3.connect(tmp)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # Search by subdomain first, then by parent domain (portal may set .epd-portal.ru cookies)
            narrow = f"%{domain.lstrip('.')}%"
            wide = "%epd-portal.ru%"

            cur.execute("""
                SELECT name, encrypted_value, value, host_key
                FROM cookies
                WHERE host_key LIKE ? OR host_key LIKE ?
                ORDER BY last_access_utc DESC
            """, (narrow, wide))

            cookies = {}
            for row in cur.fetchall():
                name = row["name"]
                raw = row["encrypted_value"] or b""
                plain = row["value"] or ""

                if raw:
                    decrypted = _decrypt_cookie_value(raw, key, name)
                    if decrypted:
                        plain = decrypted

                if name and plain:
                    cookies[name] = plain

            conn.close()

            if cookies:
                log.info(f"Found {len(cookies)} cookies: {list(cookies.keys())[:6]}")
                return cookies

            # Debug: show what domains ARE in this browser's cookie db
            try:
                conn2 = sqlite3.connect(str(tmp))
                cur2 = conn2.cursor()
                cur2.execute("SELECT DISTINCT host_key FROM cookies ORDER BY last_access_utc DESC LIMIT 30")
                all_hosts = [r[0] for r in cur2.fetchall()]
                conn2.close()
                log.info(f"No portal cookies. Recent host_keys in this browser: {all_hosts}")
            except Exception as dbg_err:
                log.debug(f"Debug host_keys failed: {dbg_err}")
        except Exception as e:
            log.warning(f"Cookie read error for {cookie_file}: {e}")
        finally:
            try:
                tmp.unlink()
            except:
                pass

    log.error("No browser cookies found!")
    return {}

# ---------- Portal API ----------
def _headers(cookies: dict) -> dict:
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "ru-RU,ru;q=0.9",
        "Content-Type": "application/json",
        "Origin": PORTAL,
        "Referer": f"{PORTAL}/ru/reservations",
    }

def check_session(cookies: dict) -> dict | None:
    """Returns user info or None if session expired."""
    try:
        r = httpx.get(
            f"{PORTAL}/auth/Account/GetCurrentUser?isTso=false",
            headers=_headers(cookies), cookies=cookies,
            follow_redirects=False, timeout=15,
        )
        if r.status_code == 200:
            try:
                return r.json()
            except:
                return {"status": "ok"}
        log.warning(f"GetCurrentUser → {r.status_code}")
        return None
    except Exception as e:
        log.error(f"Session check error: {e}")
        return None

def search_reservations(cookies: dict) -> list | None:
    """Returns list of reservations or None on auth error."""
    try:
        r = httpx.post(
            f"{PORTAL}/reservations-api/v1/Search",
            headers=_headers(cookies), cookies=cookies,
            json={"commonParams": {"pageIndex": 0, "pageSize": 20}, "filters": {}},
            follow_redirects=False, timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            return data.get("items", data) if isinstance(data, dict) else data
        if r.status_code == 401:
            return None
        log.error(f"Search → {r.status_code}: {r.text[:150]}")
        return []
    except Exception as e:
        log.error(f"Search error: {e}")
        return []

def reserve_checkpoint(reservation_id: str, cookies: dict) -> dict:
    """Book a slot for given reservation. Returns {success, error?}."""
    try:
        r = httpx.post(
            f"{PORTAL}/reservations-api/v1/ReserveCheckpoint",
            params={"reservationId": reservation_id},
            headers=_headers(cookies), cookies=cookies,
            json={},
            follow_redirects=False, timeout=20,
        )
        if r.status_code in (200, 201, 204):
            return {"success": True}
        if r.status_code == 401:
            return {"success": False, "session_expired": True}

        err = r.text[:200]
        # Known error codes from portal JS
        if "41102" in err:
            return {"success": False, "error": "Все слоты заняты (41102)"}
        if "41104" in err:
            return {"success": False, "error": "Слоты не найдены (41104)"}
        return {"success": False, "error": f"HTTP {r.status_code}: {err[:80]}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ---------- Main logic ----------
def run():
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    log.info(f"=== GIS EPD Slot Grabber started at {now} ===")

    # 1. Get browser cookies
    cookies = get_cookies_for_domain(".eopp.epd-portal.ru")
    if not cookies:
        msg = f"[{now}] Ошибка: куки браузера не найдены. Войдите в eopp.epd-portal.ru через Яндекс браузер."
        log.error(msg)
        send_tg(f"⚠️ ГИС ЭПД: {msg}")
        return

    # 2. Check session
    user = check_session(cookies)
    if user is None:
        msg = f"[{now}] Сессия истекла. Войдите в eopp.epd-portal.ru заново."
        log.error(msg)
        send_tg(f"⚠️ ГИС ЭПД: {msg}")
        return

    name = user.get("fullName") or user.get("login") or "пользователь"
    log.info(f"Session OK: {name}")

    # 3. Get reservations
    reservations = search_reservations(cookies)
    if reservations is None:
        msg = f"[{now}] Сессия истекла при поиске заявок."
        log.error(msg)
        send_tg(f"⚠️ ГИС ЭПД: {msg}")
        return

    log.info(f"Found {len(reservations)} reservation(s)")

    if not reservations:
        log.info("No active reservations — nothing to book")
        return

    # 4. Try to book slots
    booked = []
    errors = []

    for item in reservations:
        res_id = str(
            item.get("id") or item.get("reservationRequestId") or
            item.get("reservationId") or ""
        )
        if not res_id:
            log.warning(f"Reservation missing ID: {list(item.keys())[:5]}")
            continue

        status = item.get("status")
        log.info(f"Reservation {res_id} status={status}")

        result = reserve_checkpoint(res_id, cookies)

        if result["success"]:
            booked.append(res_id)
            log.info(f"✓ Slot booked for {res_id}")
        elif result.get("session_expired"):
            msg = f"[{now}] Сессия истекла при бронировании. Войдите в портал заново."
            log.error(msg)
            send_tg(f"⚠️ ГИС ЭПД: {msg}")
            return
        else:
            err = result.get("error", "неизвестная ошибка")
            errors.append(f"{res_id}: {err}")
            log.warning(f"✗ {res_id}: {err}")

    # 5. Report
    if booked:
        msg = f"✅ ГИС ЭПД [{now}]: забронировано {len(booked)} слот(ов).\nЗаявки: {', '.join(booked)}"
        log.info(msg)
        send_tg(msg)
    elif errors:
        msg = f"❌ ГИС ЭПД [{now}]: не удалось забронировать.\n" + "\n".join(errors[:5])
        log.error(msg)
        send_tg(msg)
    else:
        log.info("No bookable reservations found")

    log.info("=== Done ===")

if __name__ == "__main__":
    run()
