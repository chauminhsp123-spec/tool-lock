# -*- coding: utf-8 -*-
"""
KLive DIRECT API ALL-ROOM CHAT MONITOR V3
=========================================

KHÔNG mở Chrome / Edge.
KHÔNG mở từng tab room.

Luồng:
    1) GET /api/front/lives trực tiếp
    2) Tạo vn-sign đúng logic frontend KLive
    3) Giải mã response.sec bằng AES-ECB + PKCS7
    4) Lấy một phát danh sách room: uid / vid / nickname / isLive / title
    5) Lọc room LIVE
    6) Một WebSocket chung -> SUB toàn bộ VID
    7) Nhận mọi comment action=send, msg_type=0
    8) Mỗi 5 phút quét lại danh sách LIVE; room mới SUB ngay
    9) BLV/IDOL comment -> gửi Telegram

Nếu /front/lives thiếu VID cho một room, tool mới fallback gọi
/api/LiStre/getRoomInfo trực tiếp cho room đó (vẫn KHÔNG dùng browser).

Cài:
    pip install requests websocket-client pycryptodome

Chỉ dùng với website/tài khoản bạn có quyền truy cập/kiểm thử.
Không hard-code token của bạn trong source.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import queue
import re
import socket
import ssl
import threading
import time
import tkinter as tk
import zlib
from dataclasses import dataclass
from pathlib import Path
from ctypes import wintypes
from tkinter import messagebox, ttk
from typing import Any, Callable
from urllib.parse import quote, urlparse

import requests
import websocket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


APP_TITLE = "KLive DIRECT API • ALL LIVE CHAT MONITOR V5 24/7 STABLE"

ORIGIN = "https://www.klive.vip"
REFERER = "https://www.klive.vip/klive"
API_LIVES = "/api/front/lives"
API_ROOM_INFO = "/api/LiStre/getRoomInfo"
WSS_URL = "wss://www.klive.vip/wss/"

CHANNEL = "klive"

# Logic frontend KLive đã được bóc từ bundle hiện tại.
_SIGN_SECRET = "TMKBYg)Hs$}=e*p]^2!VD&N?"
_AES_KEY = b"ckG8PDZedJWBOvi5"

DEFAULT_VERSION = "rw-2026-08-26"
DEFAULT_MODEL = "Chrome_152.0.0.0"
DEFAULT_OS = "Windows_10"
DEFAULT_BRAND = "_"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/100.0.4896.75 Safari/537.36"
)

DEFAULT_SCAN_SECONDS = 300
DEFAULT_LIMIT = 100
HEART_SECONDS = 10
RECONNECT_MAX = 15

# V5 24/7 stability
WATCHDOG_INTERVAL = 30
PING_INTERVAL = 60
PONG_GRACE_SECONDS = 30
SUB_RETRY_SECONDS = 15
SUB_RETRY_MAX = 3
WSS_ROTATE_SECONDS = 6 * 60 * 60
TELEGRAM_QUEUE_MAX = 2000
API_RETRY_DELAYS = (0, 2, 5)
API_FAILURE_RETRY_SECONDS = 60

CHAT_HISTORY_MAX = 5000
LOG_MAX = 1500
LOG_FILE_MAX_BYTES = 5 * 1024 * 1024

if os.environ.get("APPDATA"):
    APP_DIR = Path(os.environ["APPDATA"]) / "KLive_Direct_AllRoom_V3"
else:
    APP_DIR = Path.home() / ".klive_direct_allroom_v3"
APP_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = APP_DIR / "config.json"
SESSION_FILE = APP_DIR / "session.dpapi"
LOG_FILE = APP_DIR / "klive_v5.log"


# ============================================================
# Helpers
# ============================================================

def now_hms() -> str:
    return time.strftime("%H:%M:%S")


def clean_token(value: str) -> str:
    return re.sub(r"\s+", "", str(value or "").strip())


def mask_secret(value: str) -> str:
    s = str(value or "").strip()
    if not s:
        return "(trống)"
    if len(s) <= 16:
        return s[:4] + "***"
    return s[:7] + "..." + s[-5:]


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _bytes_to_blob(data: bytes):
    buf = ctypes.create_string_buffer(data, len(data))
    blob = _DATA_BLOB(
        len(data),
        ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)),
    )
    return blob, buf


def dpapi_protect_text(text: str) -> str:
    """Mã hóa bằng Windows DPAPI, chỉ Windows user hiện tại giải được."""
    if os.name != "nt":
        raise RuntimeError("DPAPI chỉ hỗ trợ Windows")

    raw = text.encode("utf-8")
    in_blob, in_buf = _bytes_to_blob(raw)
    out_blob = _DATA_BLOB()

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "KLive V3.1 session",
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError()

    try:
        protected = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return base64.b64encode(protected).decode("ascii")
    finally:
        kernel32.LocalFree(out_blob.pbData)


def dpapi_unprotect_text(encoded: str) -> str:
    """Giải mã session DPAPI của chính Windows user đã lưu."""
    if os.name != "nt":
        raise RuntimeError("DPAPI chỉ hỗ trợ Windows")

    protected = base64.b64decode(encoded)
    in_blob, in_buf = _bytes_to_blob(protected)
    out_blob = _DATA_BLOB()

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError()

    try:
        raw = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return raw.decode("utf-8")
    finally:
        kernel32.LocalFree(out_blob.pbData)


def js_imul(a: int, b: int) -> int:
    """Math.imul tương đương JS, trả signed int32."""
    res = ((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)) & 0xFFFFFFFF
    return res - 0x100000000 if res >= 0x80000000 else res


def urshift(x: int, n: int) -> int:
    """Unsigned right shift JS >>>."""
    return (x & 0xFFFFFFFF) >> n


def frontend_hash(text: str) -> str:
    """
    Port chính xác hàm NL() của frontend:
      2 state int32 + Math.imul + unsigned shifts -> 16 hex chars.
    """
    a = 3735928559
    b = 1103547991
    for byte in text.encode("utf-8"):
        a = js_imul(a ^ byte, 2654435761)
        b = js_imul(b ^ byte, 1597334677)

    a = (
        js_imul(a ^ urshift(a, 16), 2246822507)
        ^ js_imul(b ^ urshift(b, 13), 3266489909)
    )
    b = (
        js_imul(b ^ urshift(b, 16), 2246822507)
        ^ js_imul(a ^ urshift(a, 13), 3266489909)
    )
    return f"{a & 0xFFFFFFFF:08x}{b & 0xFFFFFFFF:08x}"


def request_path_tail(request_url: str) -> str:
    """
    Frontend:
      pathname.split("/")
        .filter(Boolean)
        .map(segment => segment.slice(-1))
        .reverse()
        .join("")
    """
    try:
        if re.match(r"^https?://", request_url, re.I):
            pathname = urlparse(request_url).path
        else:
            pathname = request_url.split("?", 1)[0]
    except Exception:
        pathname = request_url.split("?", 1)[0]

    lasts = [seg[-1:] for seg in pathname.split("/") if seg]
    lasts.reverse()
    return "".join(lasts)


def normalize_sign_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def make_vn_sign(
    request_url: str,
    params: dict[str, Any],
    timestamp: str,
    visitor: str,
    oaid: str,
    version: str,
    current_href: str = REFERER,
) -> str:
    """
    Port hàm LL()/DL() trong frontend KLive.

    Sign input:
      sorted query/body primitive params
      secret
      window.location.host
      window.location.href
      path-tail
      vn-time
      visitor
      oaid
      version
    """
    clean_params: dict[str, str] = {}
    for key, value in (params or {}).items():
        if value is not None:
            clean_params[str(key)] = normalize_sign_value(value)

    query_part = ""
    for key in sorted(clean_params.keys()):
        query_part += f"&{key}={clean_params[key]}"

    host = urlparse(current_href).netloc
    tail = request_path_tail(request_url)

    raw = (
        f"{query_part}&_={_SIGN_SECRET}"
        f"#{host}"
        f"#{current_href}"
        f"#{tail}"
        f"#{timestamp}"
        f"#{visitor}"
        f"#{oaid}"
        f"#{version}"
    )
    return frontend_hash(raw)


def decrypt_sec(sec: str) -> Any:
    """
    Frontend:
        CryptoJS.AES.decrypt(sec, Utf8.parse(key), ECB, Pkcs7)
    Sau decrypt:
        - UTF-8 JSON bình thường, hoặc
        - zlib stream (78 9c / 78 da / ...)
    """
    if not isinstance(sec, str) or not sec.strip():
        raise ValueError("sec trống")

    try:
        encrypted = base64.b64decode(sec)
    except Exception as exc:
        raise ValueError(f"sec không phải Base64 hợp lệ: {exc}") from exc

    if not encrypted or len(encrypted) % AES.block_size != 0:
        raise ValueError("Độ dài ciphertext AES không hợp lệ")

    cipher = AES.new(_AES_KEY, AES.MODE_ECB)
    plain_padded = cipher.decrypt(encrypted)

    try:
        plain = unpad(plain_padded, AES.block_size, style="pkcs7")
    except Exception as exc:
        raise ValueError(f"PKCS7 unpad lỗi: {exc}") from exc

    # Frontend ưu tiên UTF-8. Nếu bytes là zlib thì decompress.
    try:
        text = plain.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = zlib.decompress(plain).decode("utf-8")
        except Exception as exc:
            raise ValueError(
                f"Decrypt thành công nhưng không decode UTF-8/zlib được; "
                f"hex={plain[:32].hex()}: {exc}"
            ) from exc

    text = text.strip()
    if not text:
        raise ValueError("Decrypt sec ra chuỗi rỗng")

    try:
        return json.loads(text)
    except Exception as exc:
        raise ValueError(f"Decrypt sec được nhưng JSON lỗi: {exc}; preview={text[:180]}") from exc


def parse_curl_headers(text: str) -> dict[str, str]:
    """
    Parse nhanh cURL DevTools để nhập:
      token, vn-visitor, vn-oaid, vn-version, cookie
    """
    raw = str(text or "")
    out: dict[str, str] = {}

    def header(name: str) -> str:
        patterns = [
            rf"-H\s+'{re.escape(name)}:\s*([^']*)'",
            rf'-H\s+"{re.escape(name)}:\s*([^"]*)"',
            rf"--header\s+'{re.escape(name)}:\s*([^']*)'",
            rf'--header\s+"{re.escape(name)}:\s*([^"]*)"',
        ]
        for pat in patterns:
            m = re.search(pat, raw, flags=re.I | re.S)
            if m:
                return m.group(1).strip()
        return ""

    for name in ("token", "vn-visitor", "vn-oaid", "vn-version"):
        value = header(name)
        if value:
            out[name] = value

    cookie_patterns = [
        r"-b\s+'([^']*)'",
        r'-b\s+"([^"]*)"',
        r"--cookie\s+'([^']*)'",
        r'--cookie\s+"([^"]*)"',
    ]
    for pat in cookie_patterns:
        m = re.search(pat, raw, flags=re.I | re.S)
        if m:
            out["cookie"] = m.group(1).strip()
            break

    return out


# ============================================================
# Data
# ============================================================

@dataclass
class Room:
    uid: str
    vid: str
    nickname: str
    title: str
    room_id: str = ""
    heat: str = ""
    is_live: bool = True
    sub_status: str = "WAIT"

    @property
    def label(self) -> str:
        name = self.nickname.strip() or self.title.strip() or f"Room {self.uid}"
        return f"{name} [{self.uid}]"


class UiBus:
    def __init__(self) -> None:
        self.q: queue.Queue[tuple[Any, ...]] = queue.Queue(maxsize=12000)

    def emit(self, *event: Any) -> None:
        try:
            self.q.put_nowait(tuple(event))
        except queue.Full:
            try:
                self.q.get_nowait()
            except queue.Empty:
                pass
            try:
                self.q.put_nowait(tuple(event))
            except queue.Full:
                pass


# ============================================================
# Direct API
# ============================================================

class KLiveDirectApi:
    def __init__(
        self,
        token: str,
        visitor: str,
        oaid: str,
        version: str,
        cookie: str = "",
        emit: Callable[..., None] | None = None,
    ) -> None:
        self.token = clean_token(token)
        self.visitor = str(visitor or "").strip()
        self.oaid = str(oaid or "").strip()
        self.version = str(version or DEFAULT_VERSION).strip() or DEFAULT_VERSION
        self.cookie = str(cookie or "").strip()
        self.emit = emit or (lambda *args: None)

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_UA})
        self._server_time_offset = 0.0
        self._primed = False

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass

    def prime(self) -> None:
        if self._primed:
            return
        self._primed = True
        # Chỉ để session nhận cookie thông thường nếu server cấp.
        # Không phụ thuộc browser/JS.
        try:
            self.session.get(
                REFERER,
                headers={
                    "User-Agent": DEFAULT_UA,
                    "Accept": "text/html,application/xhtml+xml",
                    "Accept-Language": "vi,en-US;q=0.9,en;q=0.8",
                },
                timeout=8,
            )
        except Exception:
            pass

    def _timestamp(self) -> str:
        return str(int(time.time() + self._server_time_offset))

    def _headers(self, path: str, params: dict[str, Any]) -> dict[str, str]:
        ts = self._timestamp()
        query = dict(params or {})
        query.setdefault("channel_code", CHANNEL)

        sign = make_vn_sign(
            request_url=ORIGIN + path,
            params=query,
            timestamp=ts,
            visitor=self.visitor,
            oaid=self.oaid,
            version=self.version,
            current_href=REFERER,
        )

        headers = {
            "accept": "*/*",
            "accept-language": "vi,en-US;q=0.9,en;q=0.8",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "origin": ORIGIN,
            "referer": REFERER,
            "token": self.token,
            "user-agent": DEFAULT_UA,
            "vn-brand": DEFAULT_BRAND,
            "vn-channel": CHANNEL,
            "vn-model": DEFAULT_MODEL,
            "vn-oaid": self.oaid,
            "vn-sign": sign,
            "vn-time": ts,
            "vn-version": self.version,
            "vn-version-os": DEFAULT_OS,
            "vn-visitor": self.visitor,
            "x-accept-language": "vi",
            "x-local-zone": "+0700",
        }
        if self.cookie:
            headers["cookie"] = self.cookie
        return headers

    def _decode_payload(self, obj: dict[str, Any]) -> Any:
        data = obj.get("data")
        if data is not None:
            return data
        sec = obj.get("sec")
        if isinstance(sec, str) and sec:
            return decrypt_sec(sec)
        return None

    def get(self, path: str, query: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
        if not self.visitor:
            raise RuntimeError("Thiếu vn-visitor")
        if not self.oaid:
            raise RuntimeError("Thiếu vn-oaid")

        self.prime()

        params = dict(query or {})
        params["channel_code"] = CHANNEL

        headers = self._headers(path, params)
        url = ORIGIN + path

        try:
            resp = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=15,
            )
        except Exception as exc:
            raise RuntimeError(f"HTTP connect lỗi: {exc}") from exc

        # Đồng bộ offset theo header vn-time giống frontend.
        try:
            server_time = resp.headers.get("vn-time")
            if server_time:
                value = float(server_time)
                self._server_time_offset = value - time.time()
        except Exception:
            pass

        if resp.status_code != 200:
            body = resp.text[:600]
            raise RuntimeError(f"HTTP {resp.status_code}: {body}")

        try:
            obj = resp.json()
        except Exception as exc:
            raise RuntimeError(f"Response không phải JSON: {resp.text[:500]}") from exc

        if not isinstance(obj, dict):
            raise RuntimeError(f"Response JSON sai dạng: {type(obj).__name__}")

        code = obj.get("code")
        if code not in (0, "0", None):
            raise RuntimeError(f"API code={code}: {obj.get('msg', '')}")

        try:
            data = self._decode_payload(obj)
        except Exception as exc:
            raise RuntimeError(f"Giải mã sec lỗi: {exc}") from exc

        return data, obj

    def fetch_room_info(self, uid: str) -> dict[str, Any]:
        data, _ = self.get(
            API_ROOM_INFO,
            {
                "uid": str(uid),
                "videoType": "m3u8",
            },
        )
        return data if isinstance(data, dict) else {}

    def fetch_live_rooms(self) -> tuple[list[Room], dict[str, Any]]:
        """
        Ưu tiên 1 phát limit=100.
        Nếu backend giới hạn, fallback limit=20 và page tiếp theo khi thật sự cần.
        """
        first_error: Exception | None = None
        result_data: Any = None
        meta: dict[str, Any] = {}

        for limit in (DEFAULT_LIMIT, 20):
            try:
                result_data, raw = self.get(
                    API_LIVES,
                    {
                        "type": -1,
                        "limit": limit,
                    },
                )
                meta = raw
                break
            except Exception as exc:
                first_error = exc
                if limit == 20:
                    raise
                self.emit("log", f"limit={DEFAULT_LIMIT} không được, fallback limit=20: {exc}")

        if result_data is None and first_error:
            raise first_error

        items: list[Any]
        if isinstance(result_data, list):
            items = result_data
        elif isinstance(result_data, dict):
            # Fallback chịu được backend đổi wrapper.
            for key in ("items", "list", "rows", "data"):
                value = result_data.get(key)
                if isinstance(value, list):
                    items = value
                    break
            else:
                items = []
        else:
            items = []

        page = meta.get("page") if isinstance(meta, dict) else None
        all_count = 0
        has_next = False
        page_size = len(items)
        now_page = 1
        if isinstance(page, dict):
            try:
                all_count = int(page.get("allCount") or 0)
            except Exception:
                all_count = 0
            has_next = bool(page.get("hasNextPage"))
            try:
                page_size = int(page.get("pageSize") or page_size or 20)
            except Exception:
                pass
            try:
                now_page = int(page.get("nowPage") or 1)
            except Exception:
                pass

        # Nếu một request đã đủ thì dừng đúng tinh thần "lấy 1 phát".
        # Chỉ page tiếp nếu server nói còn thiếu.
        if (has_next or (all_count and len(items) < all_count)) and page_size > 0:
            seen_raw_ids = set()
            for x in items:
                if isinstance(x, dict):
                    seen_raw_ids.add(str(x.get("id") or x.get("uid") or ""))

            page_no = now_page + 1
            max_pages = 10
            while len(items) < all_count and page_no <= max_pages:
                try:
                    more, raw_more = self.get(
                        API_LIVES,
                        {
                            "type": -1,
                            "limit": page_size,
                            "page": page_no,
                        },
                    )
                except Exception as exc:
                    self.emit("log", f"Không lấy được page {page_no}: {exc}")
                    break

                if not isinstance(more, list) or not more:
                    break

                added = 0
                for x in more:
                    if not isinstance(x, dict):
                        continue
                    key = str(x.get("id") or x.get("uid") or "")
                    if key and key in seen_raw_ids:
                        continue
                    if key:
                        seen_raw_ids.add(key)
                    items.append(x)
                    added += 1

                if added == 0:
                    break
                page_no += 1

        rooms: list[Room] = []
        seen_uid: set[str] = set()

        for item in items:
            if not isinstance(item, dict):
                continue

            uid = str(item.get("uid") or "").strip()
            if not uid or uid in seen_uid:
                continue

            is_live_value = item.get("isLive")
            try:
                is_live = int(is_live_value) == 1
            except Exception:
                is_live = bool(is_live_value)

            if not is_live:
                continue

            vid = str(item.get("vid") or "").strip()
            nickname = str(
                item.get("userNickname")
                or item.get("user_nickname")
                or ""
            ).strip()
            title = str(item.get("title") or item.get("title_main") or "").strip()
            room_id = str(item.get("id") or "").strip()
            heat = str(item.get("heat") or "")

            # Schema /front/lives cho phép vid optional.
            # Nếu đúng lúc backend chưa nhét VID vào list, lấy detail trực tiếp.
            if not vid:
                try:
                    detail = self.fetch_room_info(uid)
                    vid = str(detail.get("vid") or "").strip()
                    info = detail.get("info")
                    user_data = detail.get("userData")
                    if isinstance(info, dict):
                        title = title or str(info.get("title") or "").strip()
                    if isinstance(user_data, dict):
                        nickname = nickname or str(user_data.get("user_nickname") or "").strip()
                except Exception as exc:
                    self.emit("log", f"Room {uid}: list thiếu VID, getRoomInfo lỗi: {exc}")

            seen_uid.add(uid)
            rooms.append(
                Room(
                    uid=uid,
                    vid=vid,
                    nickname=nickname,
                    title=title,
                    room_id=room_id,
                    heat=heat,
                    is_live=True,
                    sub_status="READY" if vid else "NO VID",
                )
            )

        return rooms, {
            "allCount": all_count,
            "pageSize": page_size,
            "rawItemCount": len(items),
        }


# ============================================================
# Shared WSS: 1 socket SUB toàn bộ VID
# ============================================================

class SharedAllRoomSocket:
    """
    V5 24/7:
    - 1 WSS SUB tất cả VID.
    - Heart 10s.
    - TCP keepalive.
    - WebSocket protocol ping/pong watchdog (tự disable pong-check nếu gateway không hỗ trợ).
    - SUB thiếu được resend riêng, quá số lần mới reconnect.
    - Room mới SUB ngay, room OFF bỏ local.
    - Chủ động rotate WSS mỗi 6 giờ để tránh socket già/nửa sống nửa chết.
    - Mọi send được serialize bằng lock.
    """

    def __init__(
        self,
        token: str,
        cookie: str,
        emit: Callable[..., None],
    ) -> None:
        self.token = clean_token(token)
        self.cookie = str(cookie or "").strip()
        self.emit = emit

        self._rooms_lock = threading.RLock()
        self._state_lock = threading.RLock()
        self._ws_lock = threading.RLock()
        self._send_lock = threading.RLock()

        self._rooms_by_vid: dict[str, Room] = {}
        self.confirmed: set[str] = set()
        self._sub_sent_at: dict[str, float] = {}
        self._sub_retries: dict[str, int] = {}

        self._ws: websocket.WebSocket | None = None
        self._stop = threading.Event()
        self._restart = threading.Event()

        self._thread: threading.Thread | None = None
        self._watchdog_thread: threading.Thread | None = None

        self.connected = False
        self.connected_since_mono = 0.0
        self.connected_since_wall = 0.0

        self.last_rx_wall = 0.0
        self.last_chat_wall = 0.0
        self.last_heart_wall = 0.0
        self.last_ping_mono = 0.0
        self.last_pong_mono = 0.0
        self.last_pong_wall = 0.0
        self.pong_supported: bool | None = None

        self.connect_count = 0
        self.reconnect_count = 0
        self.restart_count = 0
        self.sub_repair_count = 0
        self.last_error = ""
        self.last_restart_reason = ""

    # ---------- state ----------
    def snapshot_rooms(self) -> dict[str, Room]:
        with self._rooms_lock:
            return dict(self._rooms_by_vid)

    def health_snapshot(self) -> dict[str, Any]:
        rooms = self.snapshot_rooms()
        with self._state_lock:
            confirmed_count = len(self.confirmed.intersection(set(rooms)))
            return {
                "connected": bool(self.connected),
                "thread_alive": bool(self._thread and self._thread.is_alive()),
                "watchdog_alive": bool(self._watchdog_thread and self._watchdog_thread.is_alive()),
                "desired": len(rooms),
                "confirmed": confirmed_count,
                "connected_since": self.connected_since_wall,
                "last_rx": self.last_rx_wall,
                "last_chat": self.last_chat_wall,
                "last_heart": self.last_heart_wall,
                "last_pong": self.last_pong_wall,
                "reconnect_count": self.reconnect_count,
                "restart_count": self.restart_count,
                "sub_repair_count": self.sub_repair_count,
                "last_error": self.last_error,
                "last_restart_reason": self.last_restart_reason,
                "pong_supported": self.pong_supported,
            }

    def _set_connected(self, value: bool) -> None:
        with self._state_lock:
            self.connected = bool(value)
        self.emit("wss_state", bool(value))

    def _mark_rx(self) -> None:
        with self._state_lock:
            self.last_rx_wall = time.time()

    def _mark_chat(self) -> None:
        with self._state_lock:
            self.last_chat_wall = time.time()

    # ---------- room management ----------
    def update_rooms(self, rooms: list[Room]) -> None:
        new_map = {r.vid: r for r in rooms if r.vid}

        with self._rooms_lock:
            old_map = dict(self._rooms_by_vid)
            old_set = set(old_map)
            new_set = set(new_map)
            added = list(new_set - old_set)
            removed = list(old_set - new_set)
            self._rooms_by_vid = new_map

        with self._state_lock:
            # Giữ trạng thái SUB của room cũ sang object Room mới.
            for vid in new_set.intersection(self.confirmed):
                room = new_map.get(vid)
                if room:
                    room.sub_status = "SUBSCRIBED"
                    self.emit("room_status", room.uid, vid, "SUBSCRIBED")

            for vid in removed:
                self.confirmed.discard(vid)
                self._sub_sent_at.pop(vid, None)
                self._sub_retries.pop(vid, None)

        if removed:
            self.emit(
                "log",
                f"ROOM OFF: bỏ {len(removed)} VID khỏi bộ lọc local; WSS các phòng còn lại giữ nguyên."
            )

        if added:
            self.emit("log", f"ROOM MỚI: {len(added)} phòng -> SUB ngay.")
            for vid in added:
                self._send_sub_vid(vid, reason="NEW_ROOM")

        if new_map:
            self.start()

    # ---------- lifecycle ----------
    def start(self) -> None:
        if self._stop.is_set():
            self._stop.clear()

        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(
                target=self._run,
                daemon=True,
                name="klive-v5-shared-wss",
            )
            self._thread.start()

        if self._watchdog_thread is None or not self._watchdog_thread.is_alive():
            self._watchdog_thread = threading.Thread(
                target=self._watchdog_loop,
                daemon=True,
                name="klive-v5-watchdog",
            )
            self._watchdog_thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._restart.set()
        self._close_current_socket()
        self._set_connected(False)

    def request_restart(self, reason: str) -> None:
        if self._stop.is_set():
            return

        with self._state_lock:
            self.restart_count += 1
            self.last_restart_reason = str(reason)

        self.emit("log", f"WATCHDOG RESTART WSS: {reason}")
        self._restart.set()
        self._close_current_socket()

    def _close_current_socket(self) -> None:
        with self._ws_lock:
            ws = self._ws
            self._ws = None

        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass

    # ---------- socket ----------
    def _connect(self) -> websocket.WebSocket:
        if not self.token:
            raise RuntimeError("Token trống")

        url = f"{WSS_URL}?userToken={quote(self.token, safe='')}"
        headers = [
            f"User-Agent: {DEFAULT_UA}",
            "Accept-Language: vi,en-US;q=0.9,en;q=0.8",
            "Cache-Control: no-cache",
            "Pragma: no-cache",
        ]

        ws = websocket.create_connection(
            url,
            origin=ORIGIN,
            cookie=self.cookie or None,
            header=headers,
            timeout=12,
            enable_multithread=True,
            sslopt={"cert_reqs": ssl.CERT_REQUIRED},
            sockopt=(
                (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
            ),
        )
        ws.settimeout(1.0)

        # Windows TCP keepalive nhanh hơn default hệ điều hành.
        try:
            raw_sock = getattr(ws.sock, "sock", ws.sock)
            if hasattr(socket, "SIO_KEEPALIVE_VALS") and hasattr(raw_sock, "ioctl"):
                raw_sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 10000))
        except Exception:
            pass

        return ws

    def _safe_send_text(self, text_value: str) -> None:
        with self._ws_lock:
            ws = self._ws
        if ws is None or not self.connected:
            raise RuntimeError("WSS chưa kết nối")

        with self._send_lock:
            ws.send(text_value)

    def _safe_send_json(self, payload: dict[str, Any]) -> None:
        self._safe_send_text(json.dumps(payload, separators=(",", ":")))

    def _send_sub_vid(self, vid: str, reason: str = "SUB") -> bool:
        rooms = self.snapshot_rooms()
        room = rooms.get(vid)
        if room is None:
            return False

        if not self.connected:
            room.sub_status = "WAIT"
            self.emit("room_status", room.uid, vid, "WAIT")
            return False

        try:
            self._safe_send_json({"action": "sub", "vid": vid})
        except Exception as exc:
            self.emit("log", f"{reason} {vid} send lỗi: {exc}")
            self.request_restart(f"SUB send lỗi: {exc}")
            return False

        now = time.monotonic()
        with self._state_lock:
            self._sub_sent_at[vid] = now
            if reason.startswith("REPAIR"):
                self.sub_repair_count += 1

        room.sub_status = "SUB..."
        self.emit("room_status", room.uid, vid, "SUB...")
        return True

    def _send_sub_all(self) -> None:
        rooms = self.snapshot_rooms()

        with self._state_lock:
            self.confirmed.clear()
            self._sub_sent_at.clear()
            self._sub_retries.clear()

        self.emit("sub_reset")
        self.emit("log", f"SUB ALL: {len(rooms)} VID.")

        for index, vid in enumerate(rooms):
            if self._stop.is_set() or self._restart.is_set():
                return
            self._send_sub_vid(vid, reason="SUB_ALL")
            if index + 1 < len(rooms):
                time.sleep(0.02)

    def _send_protocol_ping(self) -> None:
        with self._ws_lock:
            ws = self._ws
        if ws is None or not self.connected:
            return

        payload = f"k5-{int(time.time())}".encode("ascii")
        with self._send_lock:
            ws.ping(payload)

        with self._state_lock:
            self.last_ping_mono = time.monotonic()

    def _recv_packet(self) -> Any:
        with self._ws_lock:
            ws = self._ws
        if ws is None:
            raise RuntimeError("WSS object mất")

        opcode, data = ws.recv_data(control_frame=True)

        # Bất kỳ frame nào từ server đều chứng minh socket đang nhận.
        self._mark_rx()

        if opcode == websocket.ABNF.OPCODE_PONG:
            now_mono = time.monotonic()
            with self._state_lock:
                self.last_pong_mono = now_mono
                self.last_pong_wall = time.time()
                self.pong_supported = True
            return None

        if opcode == websocket.ABNF.OPCODE_PING:
            # websocket-client đã tự trả PONG.
            return None

        if opcode == websocket.ABNF.OPCODE_CLOSE:
            raise RuntimeError("Server gửi CLOSE frame")

        if opcode in (websocket.ABNF.OPCODE_TEXT, websocket.ABNF.OPCODE_BINARY):
            return data

        return None

    # ---------- parser ----------
    def _handle(self, raw: Any) -> None:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if not isinstance(raw, str):
            return

        text_value = raw.strip()
        if not text_value:
            return

        try:
            data = json.loads(text_value)
        except Exception:
            return
        if not isinstance(data, dict):
            return

        action = str(data.get("action") or "").lower()

        if action == "open":
            info = data.get("info")
            user_id = ""
            if isinstance(info, dict):
                user_id = str(info.get("userId") or "")
            self.emit("log", f"WSS OPEN • userId={user_id} • fd={data.get('fd', '')}")
            return

        if action == "response":
            msg = str(data.get("msg") or "")
            prefix = "SUCCESS-SUB-"

            if msg.startswith(prefix):
                vid = msg[len(prefix):].strip()
                if vid:
                    with self._state_lock:
                        self.confirmed.add(vid)
                        self._sub_retries.pop(vid, None)

                    room = self.snapshot_rooms().get(vid)
                    if room:
                        room.sub_status = "SUBSCRIBED"
                        self.emit("room_status", room.uid, vid, "SUBSCRIBED")

                    with self._state_lock:
                        confirmed_count = len(
                            self.confirmed.intersection(set(self.snapshot_rooms()))
                        )
                    self.emit("sub_count", confirmed_count, len(self.snapshot_rooms()))
            else:
                self.emit("log", f"WSS response: {msg}")
            return

        if action != "send":
            return

        msg_type = data.get("msg_type", data.get("msgType"))
        try:
            msg_type = int(msg_type)
        except Exception:
            msg_type = -1

        if msg_type != 0:
            return

        vid = str(data.get("vid") or data.get("newMsgRoomvid") or "").strip()
        room = self.snapshot_rooms().get(vid)
        if room is None:
            return

        text_msg = str(data.get("text") or data.get("originalText") or "").strip()
        if not text_msg:
            return

        self._mark_chat()

        nickname = str(data.get("sender_nickname") or data.get("sender") or "").strip()
        sender = str(data.get("sender") or "").strip()
        server_time = str(data.get("time") or "").strip()
        time_ms = data.get("time_ms")
        msg_id = str(data.get("msg_id") or "").strip()

        is_anchor = bool(data.get("isAnchor"))
        sender_user_type = data.get("sender_user_type")
        anchor_id = str(data.get("anchor_id") or "").strip()

        self.emit(
            "chat",
            room,
            nickname,
            sender,
            text_msg,
            server_time,
            time_ms,
            msg_id,
            is_anchor,
            sender_user_type,
            anchor_id,
        )

    # ---------- watchdog ----------
    def _repair_missing_subs(self) -> None:
        rooms = self.snapshot_rooms()
        desired = set(rooms)

        with self._state_lock:
            confirmed = set(self.confirmed)
            sent_at = dict(self._sub_sent_at)
            retries = dict(self._sub_retries)

        missing = desired - confirmed
        if not missing:
            return

        now = time.monotonic()

        for vid in missing:
            last_sent = sent_at.get(vid, 0.0)
            if last_sent and now - last_sent < SUB_RETRY_SECONDS:
                continue

            retry_no = retries.get(vid, 0) + 1
            if retry_no > SUB_RETRY_MAX:
                self.request_restart(
                    f"VID {vid} không xác nhận SUB sau {SUB_RETRY_MAX} lần repair"
                )
                return

            with self._state_lock:
                self._sub_retries[vid] = retry_no

            self.emit(
                "log",
                f"SUB REPAIR {retry_no}/{SUB_RETRY_MAX}: {vid}"
            )
            self._send_sub_vid(vid, reason=f"REPAIR#{retry_no}")

    def _watchdog_check(self) -> None:
        rooms = self.snapshot_rooms()
        if not rooms or self._stop.is_set():
            return

        if self._thread is None or not self._thread.is_alive():
            self.emit("log", "WATCHDOG: WSS worker chết -> khởi động lại.")
            self.start()
            return

        if not self.connected:
            return

        now_mono = time.monotonic()

        # 1. Rotate định kỳ để tránh socket sống quá lâu.
        with self._state_lock:
            connected_since = self.connected_since_mono
        if connected_since and now_mono - connected_since >= WSS_ROTATE_SECONDS:
            self.request_restart("rotate định kỳ 6 giờ")
            return

        # 2. Protocol ping. Nếu gateway có PONG thì dùng nó làm health signal thật.
        with self._state_lock:
            last_ping = self.last_ping_mono
            last_pong = self.last_pong_mono
            pong_supported = self.pong_supported

        if not last_ping or now_mono - last_ping >= PING_INTERVAL:
            try:
                self._send_protocol_ping()
            except Exception as exc:
                self.request_restart(f"protocol ping lỗi: {exc}")
                return

        with self._state_lock:
            last_ping = self.last_ping_mono
            last_pong = self.last_pong_mono
            pong_supported = self.pong_supported

        if last_ping and last_pong < last_ping and now_mono - last_ping > PONG_GRACE_SECONDS:
            if pong_supported is True:
                self.request_restart("không nhận PONG trong thời gian cho phép")
                return
            if pong_supported is None:
                # Có gateway/CDN không expose PONG cho client API. Chỉ disable
                # tiêu chí PONG, vẫn còn heart + TCP keepalive + SUB repair + rotation.
                with self._state_lock:
                    self.pong_supported = False
                self.emit(
                    "log",
                    "WATCHDOG: không thấy PONG protocol; chuyển sang heart/TCP/SUB watchdog."
                )

        # 3. SUB phải đủ. Không dựa vào 'không có chat' vì room có thể đang im lặng.
        self._repair_missing_subs()

    def _watchdog_loop(self) -> None:
        while not self._stop.wait(WATCHDOG_INTERVAL):
            try:
                self._watchdog_check()
            except Exception as exc:
                self.emit("log", f"WATCHDOG internal lỗi: {type(exc).__name__}: {exc}")

    # ---------- main WSS loop ----------
    def _run(self) -> None:
        attempt = 0

        while not self._stop.is_set():
            rooms = self.snapshot_rooms()
            if not rooms:
                self._set_connected(False)
                if self._stop.wait(0.5):
                    break
                continue

            self._restart.clear()

            try:
                self.emit("log", f"WSS connecting • {len(rooms)} room...")
                ws = self._connect()

                with self._ws_lock:
                    self._ws = ws

                now_wall = time.time()
                now_mono = time.monotonic()

                with self._state_lock:
                    self.connect_count += 1
                    if self.connect_count > 1:
                        self.reconnect_count += 1
                    self.connected_since_mono = now_mono
                    self.connected_since_wall = now_wall
                    self.last_rx_wall = now_wall
                    self.last_error = ""
                    self.last_ping_mono = 0.0
                    self.last_pong_mono = 0.0
                    self.last_pong_wall = 0.0
                    self.pong_supported = None

                self._set_connected(True)
                attempt = 0

                # Chờ OPEN nhưng không bắt buộc.
                open_deadline = time.monotonic() + 3.0
                while (
                    time.monotonic() < open_deadline
                    and not self._stop.is_set()
                    and not self._restart.is_set()
                ):
                    try:
                        raw = self._recv_packet()
                    except websocket.WebSocketTimeoutException:
                        break
                    if raw is None:
                        continue
                    self._handle(raw)

                    try:
                        check = json.loads(
                            raw if isinstance(raw, str)
                            else raw.decode("utf-8", errors="ignore")
                        )
                        if isinstance(check, dict) and str(check.get("action", "")).lower() == "open":
                            break
                    except Exception:
                        pass

                if self._stop.is_set() or self._restart.is_set():
                    continue

                self._send_sub_all()
                last_heart_mono = time.monotonic()

                while not self._stop.is_set() and not self._restart.is_set():
                    now_mono = time.monotonic()

                    if now_mono - last_heart_mono >= HEART_SECONDS:
                        self._safe_send_text("heart")
                        last_heart_mono = now_mono
                        with self._state_lock:
                            self.last_heart_wall = time.time()

                    try:
                        raw = self._recv_packet()
                    except websocket.WebSocketTimeoutException:
                        continue

                    if raw is None:
                        continue

                    self._handle(raw)

            except Exception as exc:
                if self._stop.is_set():
                    break

                if self._restart.is_set():
                    # Watchdog/room logic chủ động restart: không backoff dài.
                    continue

                with self._state_lock:
                    self.last_error = f"{type(exc).__name__}: {exc}"

                attempt += 1
                delay = min(2 ** max(0, attempt - 1), RECONNECT_MAX)

                self.emit(
                    "log",
                    f"WSS lỗi: {type(exc).__name__}: {exc} • reconnect {delay}s"
                )
                self._set_connected(False)

                if self._stop.wait(delay):
                    break

            finally:
                self._close_current_socket()
                self._set_connected(False)

        self._set_connected(False)


# ============================================================
# GUI
# ============================================================

class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1480x900")
        self.root.minsize(1150, 720)

        self.c = {
            "bg": "#0F172A",
            "header": "#020617",
            "panel": "#111827",
            "panel2": "#1F2937",
            "input": "#0B1220",
            "border": "#334155",
            "text": "#E5E7EB",
            "muted": "#94A3B8",
            "cyan": "#22D3EE",
            "blue": "#3B82F6",
            "green": "#22C55E",
            "red": "#EF4444",
            "yellow": "#F59E0B",
            "purple": "#A855F7",
        }
        self.root.configure(bg=self.c["bg"])

        self.bus = UiBus()
        self.api: KLiveDirectApi | None = None
        self.socket: SharedAllRoomSocket | None = None

        self.rooms: dict[str, Room] = {}
        self.chat_history: list[dict[str, str]] = []
        self.chat_seen: set[str] = set()

        self.auto_stop = threading.Event()
        self.auto_thread: threading.Thread | None = None
        self.auto_running = False
        self.saved_session_loaded = False

        self.app_started_at = time.time()
        self.last_scan_attempt_at = 0.0
        self.last_scan_ok_at = 0.0
        self.api_fail_streak = 0

        # Telegram V5: bounded queue + 1 worker, không tạo vô hạn thread.
        self.telegram_queue: queue.Queue[tuple[str, list[str], str]] = queue.Queue(
            maxsize=TELEGRAM_QUEUE_MAX
        )
        self.telegram_stop = threading.Event()
        self.telegram_worker_thread = threading.Thread(
            target=self._telegram_queue_loop,
            daemon=True,
            name="klive-v5-telegram-worker",
        )
        self.telegram_worker_thread.start()

        self.token_var = tk.StringVar()
        self.visitor_var = tk.StringVar()
        self.oaid_var = tk.StringVar()
        self.version_var = tk.StringVar(value=DEFAULT_VERSION)
        self.cookie_var = tk.StringVar()
        self.scan_var = tk.IntVar(value=DEFAULT_SCAN_SECONDS)
        self.search_var = tk.StringVar()

        # Telegram / Idol watcher
        self.telegram_bot_var = tk.StringVar()
        self.telegram_chat_id_var = tk.StringVar()
        self.telegram_enabled_var = tk.BooleanVar(value=True)
        self.idol_watch_text_cache = ""

        self.status_var = tk.StringVar(value="Sẵn sàng • DIRECT API • không mở browser")
        self.live_var = tk.StringVar(value="LIVE: 0")
        self.sub_var = tk.StringVar(value="SUB: 0/0")
        self.chat_var = tk.StringVar(value="CHAT: 0")
        self.wss_var = tk.StringVar(value="WSS: OFF")
        self.health_var = tk.StringVar(value="HEALTH: chờ AUTO")

        self._load_config()
        self._style()
        self._ui()

        if self.saved_session_loaded:
            self.status_var.set(
                "Đã tự nạp phiên KLive đã lưu • chỉ cần bấm AUTO"
            )

        self.root.after(50, self._poll)
        self.root.after(1000, self._refresh_health_ui)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------- config ----------
    def _load_config(self) -> None:
        # Config thường: không chứa token/cookie.
        try:
            if CONFIG_FILE.exists():
                data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                self.version_var.set(str(data.get("version", DEFAULT_VERSION)))
                self.scan_var.set(int(data.get("scan_seconds", DEFAULT_SCAN_SECONDS)))
        except Exception:
            pass

        # Session nhạy cảm được mã hóa bằng Windows DPAPI.
        self._load_secure_session()

    def _load_secure_session(self) -> None:
        self.saved_session_loaded = False
        if os.name != "nt" or not SESSION_FILE.exists():
            return

        try:
            encoded = SESSION_FILE.read_text(encoding="ascii").strip()
            if not encoded:
                return
            payload = json.loads(dpapi_unprotect_text(encoded))

            self.token_var.set(str(payload.get("token", "")))
            self.visitor_var.set(str(payload.get("visitor", "")))
            self.oaid_var.set(str(payload.get("oaid", "")))
            self.cookie_var.set(str(payload.get("cookie", "")))
            self.telegram_bot_var.set(str(payload.get("telegram_bot_token", "")))
            self.telegram_chat_id_var.set(str(payload.get("telegram_chat_id", "")))
            self.telegram_enabled_var.set(bool(payload.get("telegram_enabled", True)))
            self.idol_watch_text_cache = ""

            saved_version = str(payload.get("version", "")).strip()
            if saved_version:
                self.version_var.set(saved_version)

            self.saved_session_loaded = bool(
                self.token_var.get().strip()
                and self.visitor_var.get().strip()
                and self.oaid_var.get().strip()
            )
        except Exception:
            # Session cũ/hỏng/được tạo bởi Windows user khác -> bỏ qua.
            self.saved_session_loaded = False

    def _save_secure_session(self) -> None:
        if os.name != "nt":
            return

        token = clean_token(self.token_var.get())
        visitor = self.visitor_var.get().strip()
        oaid = self.oaid_var.get().strip()

        if not (token and visitor and oaid):
            return

        payload = {
            "token": token,
            "visitor": visitor,
            "oaid": oaid,
            "version": self.version_var.get().strip() or DEFAULT_VERSION,
            "cookie": self.cookie_var.get().strip(),
            "telegram_bot_token": self.telegram_bot_var.get().strip(),
            "telegram_chat_id": self.telegram_chat_id_var.get().strip(),
            "telegram_enabled": bool(self.telegram_enabled_var.get()),
            "idol_watch_list": "",
            "saved_at": int(time.time()),
        }

        try:
            encrypted = dpapi_protect_text(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            )
            SESSION_FILE.write_text(encrypted, encoding="ascii")
            self.saved_session_loaded = True
        except Exception as exc:
            # Không chặn tool chỉ vì không lưu được session.
            try:
                self.log(f"Không lưu được session DPAPI: {exc}")
            except Exception:
                pass

    def _clear_secure_session(self) -> None:
        try:
            if SESSION_FILE.exists():
                SESSION_FILE.unlink()
        except Exception:
            pass

        self.token_var.set("")
        self.visitor_var.set("")
        self.oaid_var.set("")
        self.cookie_var.set("")
        self.telegram_bot_var.set("")
        self.telegram_chat_id_var.set("")
        self.idol_watch_text_cache = ""
        self.saved_session_loaded = False
        self.status_var.set("Đã xóa phiên đã nhớ")
        self.log("Đã xóa session KLive đã lưu trên máy.")

    def _save_config(self) -> None:
        try:
            CONFIG_FILE.write_text(
                json.dumps(
                    {
                        "version": self.version_var.get().strip() or DEFAULT_VERSION,
                        "scan_seconds": int(self.scan_var.get()),
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
        except Exception:
            pass

    # ---------- UI ----------
    def _style(self) -> None:
        c = self.c
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "Treeview",
            background=c["panel"],
            fieldbackground=c["panel"],
            foreground=c["text"],
            rowheight=28,
            bordercolor=c["border"],
        )
        style.map(
            "Treeview",
            background=[("selected", c["blue"])],
            foreground=[("selected", "#FFFFFF")],
        )
        style.configure(
            "Treeview.Heading",
            background=c["panel2"],
            foreground=c["cyan"],
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        style.configure("TNotebook", background=c["bg"], borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=c["panel2"],
            foreground=c["text"],
            padding=(16, 9),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", c["blue"])],
            foreground=[("selected", "#FFFFFF")],
        )

    def btn(self, parent: tk.Misc, text: str, command: Callable[[], None], bg: str) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg="#FFFFFF",
            activebackground=bg,
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            padx=12,
            pady=8,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
        )

    def entry(self, parent: tk.Misc, var: tk.Variable, width: int, show: str = "") -> tk.Entry:
        return tk.Entry(
            parent,
            textvariable=var,
            width=width,
            show=show,
            bg=self.c["input"],
            fg=self.c["text"],
            insertbackground=self.c["cyan"],
            relief="flat",
            font=("Consolas", 9),
        )

    def _ui(self) -> None:
        c = self.c

        header = tk.Frame(self.root, bg=c["header"])
        header.pack(fill="x")
        tk.Label(
            header,
            text="KLive V5 • 24/7 STABLE • ALL LIVE CHAT • BLV → MULTI TELEGRAM",
            bg=c["header"],
            fg=c["cyan"],
            font=("Segoe UI", 18, "bold"),
        ).pack(side="left", padx=16, pady=13)

        metrics = tk.Frame(header, bg=c["header"])
        metrics.pack(side="right", padx=12)
        for var, fg in (
            (self.live_var, c["green"]),
            (self.sub_var, c["yellow"]),
            (self.chat_var, c["purple"]),
            (self.wss_var, c["cyan"]),
        ):
            tk.Label(
                metrics,
                textvariable=var,
                bg=c["header"],
                fg=fg,
                font=("Segoe UI", 10, "bold"),
            ).pack(side="left", padx=8)

        auth = tk.LabelFrame(
            self.root,
            text="Phiên KLive • V3.1 tự nhớ phiên sau lần nhập đầu tiên",
            bg=c["panel"],
            fg=c["cyan"],
            font=("Segoe UI", 10, "bold"),
        )
        auth.pack(fill="x", padx=10, pady=(10, 5))

        row1 = tk.Frame(auth, bg=c["panel"])
        row1.pack(fill="x", padx=8, pady=(7, 3))

        tk.Label(row1, text="Token:", bg=c["panel"], fg=c["muted"]).pack(side="left")
        self.entry(row1, self.token_var, 37, "•").pack(side="left", padx=(4, 10), ipady=4)

        tk.Label(row1, text="Visitor:", bg=c["panel"], fg=c["muted"]).pack(side="left")
        self.entry(row1, self.visitor_var, 10).pack(side="left", padx=(4, 10), ipady=4)

        tk.Label(row1, text="OAID:", bg=c["panel"], fg=c["muted"]).pack(side="left")
        self.entry(row1, self.oaid_var, 34).pack(side="left", padx=(4, 10), ipady=4)

        self.btn(
            row1,
            "📋 NHẬP PHIÊN LẦN ĐẦU",
            self.import_curl_clipboard,
            c["blue"],
        ).pack(side="left", padx=5)

        self.btn(
            row1,
            "🗑 XÓA PHIÊN",
            self._clear_secure_session,
            c["red"],
        ).pack(side="left", padx=5)

        row2 = tk.Frame(auth, bg=c["panel"])
        row2.pack(fill="x", padx=8, pady=(3, 8))

        tk.Label(row2, text="Version:", bg=c["panel"], fg=c["muted"]).pack(side="left")
        self.entry(row2, self.version_var, 19).pack(side="left", padx=(4, 10), ipady=4)

        tk.Label(row2, text="Cookie (tuỳ chọn):", bg=c["panel"], fg=c["muted"]).pack(side="left")
        self.entry(row2, self.cookie_var, 55, "•").pack(side="left", padx=(4, 10), ipady=4)

        tk.Label(row2, text="Quét LIVE:", bg=c["panel"], fg=c["muted"]).pack(side="left")
        self.scan_var.set(300)
        tk.Label(
            row2,
            text="300 giây (5 phút)",
            bg=c["input"],
            fg=c["yellow"],
            padx=10,
            pady=4,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=4)

        # Telegram / Idol watcher
        tele = tk.LabelFrame(
            self.root,
            text="Telegram cảnh báo BLV / IDOL • TỰ ĐỘNG từ phòng LIVE",
            bg=c["panel"],
            fg=c["yellow"],
            font=("Segoe UI", 10, "bold"),
        )
        tele.pack(fill="x", padx=10, pady=(2, 5))

        tele_top = tk.Frame(tele, bg=c["panel"])
        tele_top.pack(fill="x", padx=8, pady=(6, 3))

        tk.Checkbutton(
            tele_top,
            text="Bật gửi Telegram",
            variable=self.telegram_enabled_var,
            bg=c["panel"],
            fg=c["text"],
            activebackground=c["panel"],
            activeforeground=c["text"],
            selectcolor=c["input"],
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(0, 10))

        tk.Label(tele_top, text="Bot Token:", bg=c["panel"], fg=c["muted"]).pack(side="left")
        self.entry(tele_top, self.telegram_bot_var, 34, "•").pack(side="left", padx=(4, 10), ipady=4)

        tk.Label(tele_top, text="Chat ID (cách nhau ,):", bg=c["panel"], fg=c["muted"]).pack(side="left")
        self.entry(tele_top, self.telegram_chat_id_var, 30).pack(side="left", padx=(4, 10), ipady=4)

        self.btn(
            tele_top,
            "TEST TELEGRAM",
            self.test_telegram,
            c["blue"],
        ).pack(side="left", padx=5)

        tele_bottom = tk.Frame(tele, bg=c["panel"])
        tele_bottom.pack(fill="x", padx=8, pady=(3, 7))

        tk.Label(
            tele_bottom,
            text=(
                "TỰ ĐỘNG: tên hiển thị trên card phòng LIVE (userNickname) + UID phòng "
                "được coi là BLV/IDOL. Người đó comment ở bất kỳ phòng nào → Telegram gửi ngay."
            ),
            bg=c["panel"],
            fg=c["cyan"],
            font=("Segoe UI", 9, "bold"),
            anchor="w",
            justify="left",
        ).pack(side="left", fill="x", expand=True, padx=4)

        controls = tk.Frame(self.root, bg=c["bg"])
        controls.pack(fill="x", padx=10, pady=5)

        self.btn(
            controls,
            "⚡ LẤY TẤT CẢ PHÒNG LIVE",
            self.fetch_once,
            c["purple"],
        ).pack(side="left", padx=(0, 6))
        self.btn(
            controls,
            "▶ AUTO 24/7 • QUÉT 5 PHÚT",
            self.start_auto,
            c["green"],
        ).pack(side="left", padx=6)
        self.btn(
            controls,
            "■ DỪNG",
            self.stop_auto,
            c["red"],
        ).pack(side="left", padx=6)

        tk.Label(
            controls,
            textvariable=self.status_var,
            bg=c["bg"],
            fg=c["muted"],
            font=("Segoe UI", 9),
        ).pack(side="right", padx=5)

        health_row = tk.Frame(self.root, bg=c["panel"])
        health_row.pack(fill="x", padx=10, pady=(0, 5))
        tk.Label(
            health_row,
            textvariable=self.health_var,
            bg=c["panel"],
            fg=c["cyan"],
            font=("Consolas", 9, "bold"),
            anchor="w",
        ).pack(fill="x", padx=8, pady=5)

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=10, pady=(2, 8))

        # Rooms tab
        tab_rooms = tk.Frame(nb, bg=c["bg"])
        nb.add(tab_rooms, text="TẤT CẢ PHÒNG LIVE")

        room_cols = ("uid", "nick", "vid", "title", "sub")
        self.room_tree = ttk.Treeview(tab_rooms, columns=room_cols, show="headings")
        room_heads = {
            "uid": ("UID", 90),
            "nick": ("Kênh / Nickname", 250),
            "vid": ("VID", 350),
            "title": ("Tiêu đề", 460),
            "sub": ("SUB", 130),
        }
        for key, (title, width) in room_heads.items():
            self.room_tree.heading(key, text=title)
            self.room_tree.column(key, width=width, anchor="w")
        rscroll = ttk.Scrollbar(tab_rooms, orient="vertical", command=self.room_tree.yview)
        self.room_tree.configure(yscrollcommand=rscroll.set)
        self.room_tree.pack(side="left", fill="both", expand=True)
        rscroll.pack(side="right", fill="y")

        # Chat tab
        tab_chat = tk.Frame(nb, bg=c["bg"])
        nb.add(tab_chat, text="CHAT REALTIME • TẤT CẢ PHÒNG")

        sr = tk.Frame(tab_chat, bg=c["panel"])
        sr.pack(fill="x", pady=(0, 5))
        tk.Label(sr, text="🔎 Tìm:", bg=c["panel"], fg=c["muted"]).pack(side="left", padx=8)
        se = self.entry(sr, self.search_var, 60)
        se.pack(side="left", fill="x", expand=True, padx=5, pady=7, ipady=4)
        self.search_var.trace_add("write", lambda *_: self.refresh_chat())

        chat_cols = ("time", "room", "nick", "uid", "text")
        self.chat_tree = ttk.Treeview(tab_chat, columns=chat_cols, show="headings")
        chat_heads = {
            "time": ("Thời gian", 145),
            "room": ("Phòng LIVE", 220),
            "nick": ("Người chat", 190),
            "uid": ("User ID", 90),
            "text": ("Nội dung", 700),
        }
        for key, (title, width) in chat_heads.items():
            self.chat_tree.heading(key, text=title)
            self.chat_tree.column(key, width=width, anchor="w")
        cscroll = ttk.Scrollbar(tab_chat, orient="vertical", command=self.chat_tree.yview)
        self.chat_tree.configure(yscrollcommand=cscroll.set)
        self.chat_tree.pack(side="left", fill="both", expand=True)
        cscroll.pack(side="right", fill="y")

        # Log tab
        tab_log = tk.Frame(nb, bg=c["bg"])
        nb.add(tab_log, text="LOG")
        self.log_box = tk.Text(
            tab_log,
            bg=c["input"],
            fg=c["text"],
            insertbackground=c["cyan"],
            relief="flat",
            wrap="word",
            font=("Consolas", 9),
        )
        self.log_box.pack(fill="both", expand=True)
        self.log_box.configure(state="disabled")

    # ---------- Telegram / AUTO BLV-IDOL ----------
    @staticmethod
    def _norm_name(value: str) -> str:
        # Giữ Unicode; chỉ chuẩn hóa hoa/thường và khoảng trắng.
        return " ".join(str(value or "").strip().casefold().split())

    def _current_live_blv_indexes(self) -> tuple[dict[str, Room], dict[str, list[Room]]]:
        """
        Nguồn BLV/IDOL là chính danh sách room LIVE:
          uid  = UID streamer
          nickname = userNickname trên card LIVE
        """
        uid_map: dict[str, Room] = {}
        name_map: dict[str, list[Room]] = {}

        for live_room in self.rooms.values():
            uid = str(live_room.uid or "").strip()
            if uid:
                uid_map[uid] = live_room

            name = self._norm_name(live_room.nickname)
            if name:
                name_map.setdefault(name, []).append(live_room)

        return uid_map, name_map

    def _match_current_live_blv(
        self,
        sender_uid: str,
        sender_nickname: str,
        anchor_id: str = "",
    ) -> tuple[bool, Room | None, str]:
        """
        Ưu tiên UID tuyệt đối để tránh trùng nickname.
        Chỉ fallback nickname nếu event không khớp UID.
        """
        uid_map, name_map = self._current_live_blv_indexes()

        uid = str(sender_uid or "").strip()
        anchor_uid = str(anchor_id or "").strip()

        if uid and uid in uid_map:
            return True, uid_map[uid], "UID"

        if anchor_uid and anchor_uid in uid_map:
            return True, uid_map[anchor_uid], "ANCHOR_UID"

        name = self._norm_name(sender_nickname)
        candidates = name_map.get(name, []) if name else []
        if candidates:
            return True, candidates[0], "NICKNAME"

        return False, None, ""

    @staticmethod
    def _parse_chat_ids(raw: str) -> list[str]:
        """
        Hỗ trợ nhiều Chat ID:
          123456789,987654321
        cũng chấp nhận dấu ; hoặc xuống dòng.
        """
        items = []
        seen = set()
        normalized = str(raw or "").replace(";", ",").replace("\n", ",")
        for part in normalized.split(","):
            chat_id = part.strip()
            if not chat_id or chat_id in seen:
                continue
            seen.add(chat_id)
            items.append(chat_id)
        return items

    def _telegram_send_batch(
        self,
        token: str,
        chat_ids: list[str],
        message: str,
    ) -> None:
        """Gửi tuần tự qua 1 worker cố định, có retry/rate-limit handling."""
        if not token or not chat_ids:
            return

        url = f"https://api.telegram.org/bot{token}/sendMessage"

        for chat_id in chat_ids:
            for attempt in range(3):
                if self.telegram_stop.is_set():
                    return

                try:
                    resp = requests.post(
                        url,
                        json={
                            "chat_id": chat_id,
                            "text": message,
                            "disable_web_page_preview": True,
                        },
                        timeout=12,
                    )

                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                        except Exception:
                            data = {}

                        if data.get("ok", False):
                            break

                        self.bus.emit(
                            "log",
                            f"Telegram [{chat_id}] API lỗi: {str(data)[:300]}"
                        )
                    elif resp.status_code == 429:
                        retry_after = 2
                        try:
                            data = resp.json()
                            retry_after = int(
                                (data.get("parameters") or {}).get("retry_after") or 2
                            )
                        except Exception:
                            pass

                        retry_after = max(1, min(retry_after, 15))
                        self.bus.emit(
                            "log",
                            f"Telegram [{chat_id}] rate-limit • chờ {retry_after}s"
                        )
                        if self.telegram_stop.wait(retry_after):
                            return
                        continue
                    else:
                        self.bus.emit(
                            "log",
                            f"Telegram [{chat_id}] HTTP {resp.status_code}: "
                            f"{resp.text[:250]}"
                        )

                except Exception as exc:
                    self.bus.emit(
                        "log",
                        f"Telegram [{chat_id}] lỗi attempt {attempt + 1}/3: "
                        f"{type(exc).__name__}: {exc}"
                    )

                if attempt < 2 and self.telegram_stop.wait((1, 3, 8)[attempt]):
                    return

    def _telegram_queue_loop(self) -> None:
        while not self.telegram_stop.is_set():
            try:
                token, chat_ids, message = self.telegram_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                self._telegram_send_batch(token, chat_ids, message)
            finally:
                try:
                    self.telegram_queue.task_done()
                except Exception:
                    pass

    def send_telegram(self, message: str) -> None:
        # GUI thread: snapshot Tk variables, rồi đưa vào bounded queue.
        if not bool(self.telegram_enabled_var.get()):
            return

        token = self.telegram_bot_var.get().strip()
        chat_ids = self._parse_chat_ids(self.telegram_chat_id_var.get())
        if not token or not chat_ids:
            return

        item = (token, chat_ids, message)

        try:
            self.telegram_queue.put_nowait(item)
        except queue.Full:
            # Ưu tiên cảnh báo mới nhất: bỏ 1 item cũ nhất.
            try:
                self.telegram_queue.get_nowait()
                self.telegram_queue.task_done()
            except Exception:
                pass

            try:
                self.telegram_queue.put_nowait(item)
                self.bus.emit(
                    "log",
                    "Telegram queue đầy -> bỏ cảnh báo cũ nhất để tránh tăng RAM."
                )
            except queue.Full:
                self.bus.emit("log", "Telegram queue vẫn đầy -> bỏ 1 cảnh báo.")

    def test_telegram(self) -> None:
        token = self.telegram_bot_var.get().strip()
        chat_ids = self._parse_chat_ids(self.telegram_chat_id_var.get())
        if not token or not chat_ids:
            messagebox.showwarning(APP_TITLE, "Hãy nhập Bot Token và ít nhất 1 Chat ID trước.")
            return

        self._save_secure_session()
        self.send_telegram(
            f"✅ KLive V5 24/7 Stable đã kết nối Telegram thành công.\n"
            f"Đang gửi tới {len(chat_ids)} người/chat."
        )
        self.log(f"Đã gửi TEST Telegram tới {len(chat_ids)} Chat ID.")

    # ---------- input snapshot ----------
    def snapshot(self) -> dict[str, Any]:
        # V4.1 cố định đúng yêu cầu: quét lại room mỗi 5 phút.
        scan = 300
        self.scan_var.set(300)

        return {
            "token": clean_token(self.token_var.get()),
            "visitor": self.visitor_var.get().strip(),
            "oaid": self.oaid_var.get().strip(),
            "version": self.version_var.get().strip() or DEFAULT_VERSION,
            "cookie": self.cookie_var.get().strip(),
            "scan": scan,
        }

    def validate(self, cfg: dict[str, Any]) -> bool:
        missing = []
        if not cfg["token"]:
            missing.append("Token")
        if not cfg["visitor"]:
            missing.append("vn-visitor")
        if not cfg["oaid"]:
            missing.append("vn-oaid")

        if missing:
            messagebox.showwarning(
                APP_TITLE,
                "Thiếu: " + ", ".join(missing)
                + "\n\nLần đầu: Copy as cURL request 'lives' rồi bấm "
                  "'NHẬP PHIÊN LẦN ĐẦU'. Sau đó tool tự nhớ phiên.",
            )
            return False
        return True

    def import_curl_clipboard(self) -> None:
        try:
            raw = self.root.clipboard_get()
        except Exception as exc:
            messagebox.showwarning(APP_TITLE, f"Không đọc được clipboard: {exc}")
            return

        data = parse_curl_headers(raw)
        if not data:
            messagebox.showwarning(
                APP_TITLE,
                "Clipboard không giống cURL DevTools hoặc không tìm thấy header KLive.",
            )
            return

        if data.get("token"):
            self.token_var.set(data["token"])
        if data.get("vn-visitor"):
            self.visitor_var.set(data["vn-visitor"])
        if data.get("vn-oaid"):
            self.oaid_var.set(data["vn-oaid"])
        if data.get("vn-version"):
            self.version_var.set(data["vn-version"])
        if data.get("cookie"):
            self.cookie_var.set(data["cookie"])

        self._save_config()
        self._save_secure_session()
        self.log(
            "Đã nhập + mã hóa session bằng Windows DPAPI: "
            f"token={mask_secret(data.get('token',''))}, "
            f"visitor={data.get('vn-visitor','')}, "
            f"oaid={mask_secret(data.get('vn-oaid',''))}, "
            f"version={data.get('vn-version','') or self.version_var.get()}."
        )

    # ---------- direct fetch ----------
    def make_api(self, cfg: dict[str, Any]) -> KLiveDirectApi:
        return KLiveDirectApi(
            token=cfg["token"],
            visitor=cfg["visitor"],
            oaid=cfg["oaid"],
            version=cfg["version"],
            cookie=cfg["cookie"],
            emit=self.bus.emit,
        )

    def fetch_once(self) -> None:
        cfg = self.snapshot()
        if not self.validate(cfg):
            return
        self._save_config()

        def worker() -> None:
            api = self.make_api(cfg)
            try:
                self.bus.emit("status", "Đang gọi DIRECT /api/front/lives...")
                start = time.perf_counter()
                rooms, meta = api.fetch_live_rooms()
                ms = int((time.perf_counter() - start) * 1000)
                self.bus.emit("rooms", rooms, meta)
                self.bus.emit(
                    "log",
                    f"DIRECT API OK • {len(rooms)} phòng LIVE • "
                    f"raw={meta.get('rawItemCount')} allCount={meta.get('allCount')} • {ms}ms."
                )
                self.bus.emit(
                    "status",
                    f"Đã lấy {len(rooms)} phòng LIVE trực tiếp trong {ms}ms • không browser."
                )
            except Exception as exc:
                self.bus.emit("error", f"Lấy phòng LIVE lỗi: {exc}")
            finally:
                api.close()

        threading.Thread(target=worker, daemon=True, name="klive-v3-fetch-once").start()

    # ---------- auto ----------
    def start_auto(self) -> None:
        if self.auto_running:
            self.status_var.set("AUTO đang chạy")
            return

        cfg = self.snapshot()
        if not self.validate(cfg):
            return

        self._save_config()
        self._save_secure_session()
        self.auto_stop.clear()
        self.auto_running = True

        # API + WSS giữ nguyên trong vòng AUTO.
        self.api = self.make_api(cfg)
        self.socket = SharedAllRoomSocket(
            token=cfg["token"],
            cookie=cfg["cookie"],
            emit=self.bus.emit,
        )

        self.auto_thread = threading.Thread(
            target=self._auto_loop,
            args=(cfg,),
            daemon=True,
            name="klive-v3-auto",
        )
        self.auto_thread.start()
        self.log("V5 24/7 bắt đầu • quét LIVE 5 phút/lần • WSS watchdog + SUB repair + Telegram queue.")

    def _fetch_live_rooms_with_retry(
        self,
    ) -> tuple[list[Room], dict[str, Any], int]:
        """
        Retry API riêng. Nếu API chết, WSS hiện tại vẫn chạy và nghe chat;
        tuyệt đối không thay rooms bằng [] do lỗi mạng/API.
        """
        if not self.api:
            raise RuntimeError("API client chưa có")

        last_exc: Exception | None = None

        for attempt, delay in enumerate(API_RETRY_DELAYS, start=1):
            if delay:
                if self.auto_stop.wait(delay):
                    raise RuntimeError("AUTO đang dừng")

            self.last_scan_attempt_at = time.time()
            started = time.perf_counter()

            try:
                rooms, meta = self.api.fetch_live_rooms()
                ms = int((time.perf_counter() - started) * 1000)
                self.last_scan_ok_at = time.time()
                self.api_fail_streak = 0
                return rooms, meta, ms
            except Exception as exc:
                last_exc = exc
                self.api_fail_streak += 1
                self.bus.emit(
                    "log",
                    f"API retry {attempt}/{len(API_RETRY_DELAYS)} lỗi: "
                    f"{type(exc).__name__}: {exc}"
                )

        raise last_exc or RuntimeError("API scan thất bại")

    def _auto_loop(self, cfg: dict[str, Any]) -> None:
        scan_seconds = 300  # cố định 5 phút

        while not self.auto_stop.is_set():
            scan_ok = False

            try:
                rooms, meta, ms = self._fetch_live_rooms_with_retry()
                scan_ok = True

                self.bus.emit("rooms", rooms, meta)
                self.bus.emit(
                    "log",
                    f"SCAN LIVE OK • {len(rooms)} room • "
                    f"allCount={meta.get('allCount')} • {ms}ms."
                )

                if self.socket:
                    self.socket.update_rooms(rooms)

                self.bus.emit(
                    "status",
                    f"24/7 AUTO • {len(rooms)} phòng LIVE • API {ms}ms • "
                    "quét lại sau 5 phút"
                )

            except Exception as exc:
                # QUAN TRỌNG: không đụng socket.update_rooms ở đây.
                # WSS + danh sách room cũ vẫn nghe chat.
                self.bus.emit(
                    "log",
                    f"SCAN API thất bại hoàn toàn: {type(exc).__name__}: {exc}. "
                    "WSS hiện tại vẫn giữ nguyên."
                )
                self.bus.emit(
                    "status",
                    "API đang lỗi • WSS/chat cũ vẫn chạy • thử API lại sau 60s"
                )

            wait_seconds = scan_seconds if scan_ok else API_FAILURE_RETRY_SECONDS

            deadline = time.monotonic() + wait_seconds
            while time.monotonic() < deadline:
                if self.auto_stop.wait(0.2):
                    break

        self.auto_running = False

    def stop_auto(self) -> None:
        self.auto_stop.set()
        self.auto_running = False

        if self.socket:
            self.socket.stop()
            self.socket = None

        if self.api:
            self.api.close()
            self.api = None

        self.status_var.set("Đã dừng AUTO")
        self.wss_var.set("WSS: OFF")
        self.log("Đã dừng AUTO + WSS. Telegram worker sẽ dừng khi đóng tool.")

    # ---------- rooms/chat ----------
    def apply_rooms(self, rooms: list[Room], meta: dict[str, Any]) -> None:
        old_status = {uid: room.sub_status for uid, room in self.rooms.items()}
        old_uids = set(self.rooms)
        new_uids = {room.uid for room in rooms}
        just_added = new_uids - old_uids

        self.rooms = {}
        for room in rooms:
            if room.uid in old_status and room.sub_status in {"READY", "WAIT"}:
                room.sub_status = old_status[room.uid]
            self.rooms[room.uid] = room

        self.refresh_rooms()
        self.live_var.set(f"LIVE: {len(self.rooms)}")

        if just_added and old_uids:
            names = [self.rooms[uid].label for uid in sorted(just_added) if uid in self.rooms]
            self.log(f"PHÒNG LIVE MỚI: {', '.join(names)}")

        confirmed = sum(1 for r in self.rooms.values() if r.sub_status == "SUBSCRIBED")
        self.sub_var.set(f"SUB: {confirmed}/{len(self.rooms)}")

    def refresh_rooms(self) -> None:
        existing = set(self.room_tree.get_children())

        def keyfunc(item: tuple[str, Room]) -> tuple[int, str]:
            uid = item[0]
            return (int(uid) if uid.isdigit() else 10**12, uid)

        for uid, room in sorted(self.rooms.items(), key=keyfunc):
            values = (
                uid,
                room.nickname,
                room.vid or "(NO VID)",
                room.title,
                room.sub_status,
            )
            if uid in existing:
                self.room_tree.item(uid, values=values)
                existing.remove(uid)
            else:
                self.room_tree.insert("", "end", iid=uid, values=values)

        for iid in existing:
            self.room_tree.delete(iid)

    def room_status(self, uid: str, vid: str, status: str) -> None:
        room = self.rooms.get(uid)
        if room and room.vid == vid:
            room.sub_status = status
            self.refresh_rooms()

        confirmed = sum(1 for r in self.rooms.values() if r.sub_status == "SUBSCRIBED")
        self.sub_var.set(f"SUB: {confirmed}/{len(self.rooms)}")

    def handle_chat(
        self,
        room: Room,
        nickname: str,
        sender: str,
        message: str,
        server_time: str,
        time_ms: Any,
        msg_id: str,
        is_anchor: bool = False,
        sender_user_type: Any = None,
        anchor_id: str = "",
    ) -> None:
        key = msg_id.strip() if msg_id else ""
        if not key:
            key = f"{room.vid}|{sender}|{message}|{time_ms}"

        if key in self.chat_seen:
            return

        self.chat_seen.add(key)
        if len(self.chat_seen) > 12000:
            # Giữ bộ nhớ có giới hạn.
            self.chat_seen = set(list(self.chat_seen)[-6000:])

        display_time = server_time
        if not display_time and time_ms not in (None, ""):
            try:
                ts = float(time_ms) / 1000.0
                display_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
            except Exception:
                display_time = now_hms()
        if not display_time:
            display_time = now_hms()

        # V4.1: mọi streamer đang LIVE đều tự động được xem là BLV/IDOL cần theo dõi.
        # Tên chính là userNickname lấy từ /api/front/lives (chỗ khoanh trên card).
        matched_blv, blv_room, matched_by = self._match_current_live_blv(
            sender_uid=sender,
            sender_nickname=nickname,
            anchor_id=anchor_id,
        )

        if matched_blv:
            blv_name = blv_room.nickname if blv_room and blv_room.nickname else nickname
            blv_uid = blv_room.uid if blv_room and blv_room.uid else sender
            own_live_room = blv_room.label if blv_room else "(không rõ)"

            telegram_text = (
                "🚨 BLV / IDOL VỪA COMMENT\n"
                f"⭐ BLV/IDOL: {blv_name}\n"
                f"🆔 UID: {blv_uid or '(không có)'}\n"
                f"🎥 Phòng LIVE của họ: {own_live_room}\n"
                f"📺 Comment tại: {room.label}\n"
                f"🕒 {display_time}\n"
                f"💬 {message}"
            )
            self.send_telegram(telegram_text)
            self.log(
                f"TELE AUTO-BLV [{matched_by}] "
                f"{blv_name} [{blv_uid}] @ {room.label}: {message}"
            )

        row = {
            "key": key,
            "time": display_time,
            "room": room.label,
            "nick": nickname,
            "uid": sender,
            "text": message,
        }
        self.chat_history.append(row)
        if len(self.chat_history) > CHAT_HISTORY_MAX:
            self.chat_history = self.chat_history[-CHAT_HISTORY_MAX:]

        self.chat_var.set(f"CHAT: {len(self.chat_history)}")

        needle = self.search_var.get().strip().casefold()
        if not needle or needle in " ".join(row.values()).casefold():
            iid = f"chat-{int(time.time()*1000)}-{len(self.chat_history)}"
            self.chat_tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    row["time"],
                    row["room"],
                    row["nick"],
                    row["uid"],
                    row["text"],
                ),
            )
            children = self.chat_tree.get_children()
            if len(children) > 1800:
                for old in children[:200]:
                    self.chat_tree.delete(old)
            self.chat_tree.yview_moveto(1.0)

    def refresh_chat(self) -> None:
        needle = self.search_var.get().strip().casefold()
        self.chat_tree.delete(*self.chat_tree.get_children())

        rows = self.chat_history[-1800:]
        if needle:
            rows = [
                row
                for row in rows
                if needle in " ".join(row.values()).casefold()
            ]

        for idx, row in enumerate(rows):
            self.chat_tree.insert(
                "",
                "end",
                iid=f"search-{idx}-{row['key']}",
                values=(
                    row["time"],
                    row["room"],
                    row["nick"],
                    row["uid"],
                    row["text"],
                ),
            )

        if self.chat_tree.get_children():
            self.chat_tree.yview_moveto(1.0)

    # ---------- logs/events ----------
    @staticmethod
    def _format_duration(seconds: float) -> str:
        seconds = max(0, int(seconds))
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, secs = divmod(rem, 60)

        if days:
            return f"{days}d {hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    @staticmethod
    def _age_text(timestamp: float) -> str:
        if not timestamp:
            return "—"
        age = max(0, int(time.time() - timestamp))
        if age < 60:
            return f"{age}s"
        if age < 3600:
            return f"{age // 60}m{age % 60:02d}s"
        return f"{age // 3600}h{(age % 3600) // 60:02d}m"

    def _refresh_health_ui(self) -> None:
        try:
            up = self._format_duration(time.time() - self.app_started_at)
            scan_age = self._age_text(self.last_scan_ok_at)
            tgq = self.telegram_queue.qsize()

            if self.socket:
                h = self.socket.health_snapshot()
                rx_age = self._age_text(float(h.get("last_rx") or 0))
                chat_age = self._age_text(float(h.get("last_chat") or 0))
                recon = int(h.get("reconnect_count") or 0)
                repairs = int(h.get("sub_repair_count") or 0)
                desired = int(h.get("desired") or 0)
                confirmed = int(h.get("confirmed") or 0)
                wd = "OK" if h.get("watchdog_alive") else "OFF"

                self.health_var.set(
                    f"UP {up}   |   WATCHDOG {wd}   |   "
                    f"RX {rx_age} trước   |   CHAT {chat_age} trước   |   "
                    f"SUB {confirmed}/{desired}   |   RECONNECT {recon}   |   "
                    f"SUB-REPAIR {repairs}   |   SCAN {scan_age} trước   |   TGQ {tgq}"
                )
            else:
                self.health_var.set(
                    f"UP {up}   |   WATCHDOG OFF   |   "
                    f"SCAN {scan_age} trước   |   TGQ {tgq}"
                )
        except Exception:
            pass
        finally:
            try:
                self.root.after(1000, self._refresh_health_ui)
            except Exception:
                pass

    def _write_disk_log(self, line: str) -> None:
        try:
            if LOG_FILE.exists() and LOG_FILE.stat().st_size >= LOG_FILE_MAX_BYTES:
                backup = LOG_FILE.with_suffix(".log.1")
                try:
                    if backup.exists():
                        backup.unlink()
                except Exception:
                    pass
                try:
                    LOG_FILE.replace(backup)
                except Exception:
                    pass

            with LOG_FILE.open("a", encoding="utf-8") as fp:
                fp.write(line + "\n")
        except Exception:
            pass

    def log(self, text: str) -> None:
        line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {text}"
        self._write_disk_log(line)

        self.log_box.configure(state="normal")
        self.log_box.insert("end", line + "\n")
        self.log_box.see("end")

        try:
            lines = int(self.log_box.index("end-1c").split(".")[0])
            if lines > LOG_MAX + 100:
                self.log_box.delete("1.0", f"{lines - LOG_MAX}.0")
        except Exception:
            pass

        self.log_box.configure(state="disabled")

    def _poll(self) -> None:
        count = 0
        while count < 250:
            try:
                event = self.bus.q.get_nowait()
            except queue.Empty:
                break
            count += 1

            if not event:
                continue
            kind = event[0]

            if kind == "log":
                self.log(str(event[1]))

            elif kind == "status":
                self.status_var.set(str(event[1]))

            elif kind == "error":
                self.log("LỖI: " + str(event[1]))
                self.status_var.set("Có lỗi • xem LOG")
                messagebox.showerror(APP_TITLE, str(event[1]))

            elif kind == "rooms":
                rooms = event[1]
                meta = event[2]
                self.apply_rooms(rooms, meta)

            elif kind == "room_status":
                self.room_status(str(event[1]), str(event[2]), str(event[3]))

            elif kind == "sub_reset":
                for room in self.rooms.values():
                    if room.vid:
                        room.sub_status = "WAIT"
                self.refresh_rooms()
                self.sub_var.set(f"SUB: 0/{len(self.rooms)}")

            elif kind == "sub_count":
                self.sub_var.set(f"SUB: {event[1]}/{event[2]}")

            elif kind == "wss_state":
                on = bool(event[1])
                self.wss_var.set("WSS: ON" if on else "WSS: OFF")

            elif kind == "chat":
                self.handle_chat(
                    room=event[1],
                    nickname=str(event[2]),
                    sender=str(event[3]),
                    message=str(event[4]),
                    server_time=str(event[5]),
                    time_ms=event[6],
                    msg_id=str(event[7]),
                    is_anchor=bool(event[8]) if len(event) > 8 else False,
                    sender_user_type=event[9] if len(event) > 9 else None,
                    anchor_id=str(event[10]) if len(event) > 10 else "",
                )

        self.root.after(50, self._poll)

    def on_close(self) -> None:
        self._save_config()
        self._save_secure_session()
        self.auto_stop.set()
        self.telegram_stop.set()

        if self.socket:
            try:
                self.socket.stop()
            except Exception:
                pass

        if self.api:
            try:
                self.api.close()
            except Exception:
                pass

        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
