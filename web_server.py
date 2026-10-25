# -*- coding: utf-8 -*-
"""
DouyinLiveRecorder 网页管理服务

功能:
  - 实时浏览录制目录中的视频文件 (ts/mp4/flv/mkv/音频 等)
  - 内置网页播放器 (hls.js / flv.js / 原生 video)
  - 整文件下载
  - 使用 ffmpeg 剪切并下载视频的指定片段
  - 删除视频文件需 Microsoft Authenticator 动态码 (TOTP)
  - 存储空间管理: 80GB 配额 + N 天保留, 定期删除最旧文件

纯标准库实现 (可选依赖 segno 用于生成 TOTP 二维码)。
"""
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from src.totp import (
    generate_secret,
    provisioning_uri,
    verify as totp_verify,
)
from src.utils import logger

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, 'config', 'config.ini')
WEBUI_DIR = os.path.join(BASE_DIR, 'webui')
TEXT_ENCODING = 'utf-8-sig'

WEB_SECTION = '网页服务'

DEFAULTS = {
    '是否开启网页服务(是/否)': '是',
    '网页服务监听地址': '0.0.0.0',
    '网页服务端口': '8000',
    '视频存储配额(gb)': '80',
    '视频保留天数': '3',
    '删除视频需要动态码(是/否)': '是',
    'TOTP密钥(base32)': '',
    '自动开始录制(是/否)': '是',
}

# 运行期配置
WEB_ENABLED = False
HOST = '0.0.0.0'
PORT = 8000
QUOTA_BYTES = 80 * 1024 ** 3
RETENTION_DAYS = 3.0
DELETE_REQUIRES_TOTP = True
TOTP_SECRET = ''
VIDEO_ROOT = os.path.join(BASE_DIR, 'downloads')
AUTO_START_RECORDER = True

_server_started = False
_server_lock = threading.Lock()

CONTENT_TYPES = {
    'ts': 'video/mp2t',
    'mp4': 'video/mp4',
    'm4v': 'video/mp4',
    'm3u8': 'application/vnd.apple.mpegurl',
    'flv': 'video/x-flv',
    'mkv': 'video/x-matroska',
    'webm': 'video/webm',
    'mov': 'video/quicktime',
    'mp3': 'audio/mpeg',
    'm4a': 'audio/mp4',
    'aac': 'audio/aac',
    'wav': 'audio/wav',
    'flac': 'audio/flac',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'srt': 'text/plain',
    'ass': 'text/plain',
    'vtt': 'text/vtt',
}

# 登录: 硬编码的 admin 账户, 其余任意登录均为 guest
ADMIN_USER = 'admin'
ADMIN_PASSWORD = 'admin123456'
SESSION_TTL = 7 * 24 * 3600
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()


def _read_raw() -> str:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r', encoding=TEXT_ENCODING) as f:
            return f.read()
    return ''


def _write_raw(raw: str) -> None:
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w', encoding=TEXT_ENCODING) as f:
        f.write(raw)


def _section_block(secret: str) -> str:
    values = dict(DEFAULTS)
    values['TOTP密钥(base32)'] = secret
    lines = [WEB_SECTION]
    for key in values:
        lines.append(f'{key} = {values[key]}')
    return '\n'.join(lines) + '\n'


def ensure_web_config() -> None:
    """确保 [网页服务] 配置段存在, 并自动生成 TOTP 密钥。只做最小化修改, 不破坏原有注释。"""
    raw = _read_raw()
    changed = False

    if f'[{WEB_SECTION}]' not in raw:
        secret = generate_secret()
        block = _section_block(secret)
        raw = raw.rstrip('\n') + '\n\n' + block
        _write_raw(raw)
        return

    # 补齐缺失的选项
    for key, value in DEFAULTS.items():
        pattern = re.compile(rf'^\s*{re.escape(key)}\s*=.*$', re.MULTILINE)
        if not pattern.search(raw):
            idx = raw.index(f'[{WEB_SECTION}]') + len(WEB_SECTION) + 1
            raw = raw[:idx] + f'{key} = {value}\n' + raw[idx:]
            changed = True

    # 密钥缺失则生成
    match = re.search(r'^\s*TOTP密钥\(base32\)\s*=\s*(.*)$', raw, re.MULTILINE)
    secret = match.group(1).strip() if match else ''
    if not secret:
        secret = generate_secret()
        new_line = f'TOTP密钥(base32) = {secret}'
        pattern = re.compile(r'^\s*TOTP密钥\(base32\)\s*=.*$', re.MULTILINE)
        if pattern.search(raw):
            raw = pattern.sub(new_line, raw, count=1)
        else:
            idx = raw.index(f'[{WEB_SECTION}]') + len(WEB_SECTION) + 1
            raw = raw[:idx] + new_line + '\n' + raw[idx:]
        changed = True

    if changed:
        _write_raw(raw)


def _read_parser() -> 'configparser.RawConfigParser':
    import configparser
    parser = configparser.RawConfigParser()
    parser.read(CONFIG_FILE, encoding=TEXT_ENCODING)
    return parser


def load_config() -> None:
    global WEB_ENABLED, HOST, PORT, QUOTA_BYTES, RETENTION_DAYS
    global DELETE_REQUIRES_TOTP, TOTP_SECRET, VIDEO_ROOT, AUTO_START_RECORDER

    ensure_web_config()
    parser = _read_parser()

    def get(section: str, option: str, default: str) -> str:
        try:
            return parser.get(section, option)
        except Exception:
            return str(default)

    WEB_ENABLED = get(WEB_SECTION, '是否开启网页服务(是/否)', '否').strip() == '是'
    HOST = get(WEB_SECTION, '网页服务监听地址', '0.0.0.0').strip() or '0.0.0.0'
    try:
        PORT = int(get(WEB_SECTION, '网页服务端口', '8000').strip())
    except ValueError:
        PORT = 8000
    try:
        QUOTA_BYTES = int(float(get(WEB_SECTION, '视频存储配额(gb)', '80').strip()) * 1024 ** 3)
    except ValueError:
        QUOTA_BYTES = 80 * 1024 ** 3
    try:
        RETENTION_DAYS = float(get(WEB_SECTION, '视频保留天数', '3').strip())
    except ValueError:
        RETENTION_DAYS = 3.0
    DELETE_REQUIRES_TOTP = get(WEB_SECTION, '删除视频需要动态码(是/否)', '是').strip() == '是'
    TOTP_SECRET = get(WEB_SECTION, 'TOTP密钥(base32)', '').strip()
    AUTO_START_RECORDER = get(WEB_SECTION, '自动开始录制(是/否)', '是').strip() == '是'

    save_path = get('录制设置', '直播保存路径(不填则默认)', '').strip()
    if save_path:
        VIDEO_ROOT = os.path.abspath(save_path)
    else:
        VIDEO_ROOT = os.path.join(BASE_DIR, 'downloads')
    os.makedirs(VIDEO_ROOT, exist_ok=True)


def safe_path(rel: str) -> str | None:
    """将客户端传入的相对路径解析到视频根目录内, 防止路径穿越。"""
    root = os.path.realpath(VIDEO_ROOT)
    candidate = os.path.realpath(os.path.join(root, rel))
    if candidate == root or not candidate.startswith(root + os.sep):
        return None
    return candidate


def get_duration(path: str) -> float | None:
    """通过 ffprobe 获取媒体时长(秒), 失败返回 None。"""
    try:
        out = subprocess.check_output(
            ['ffprobe', '-v', 'error', '-show_entries', 'format=duration',
             '-of', 'default=noprint_wrappers=1:nokey=1', path],
            stderr=subprocess.DEVNULL, timeout=30
        )
        return float(out.decode().strip())
    except Exception:
        return None


def content_type(path: str) -> str:
    ext = os.path.splitext(path)[1].lstrip('.').lower()
    return CONTENT_TYPES.get(ext, 'application/octet-stream')


# ---------- 录制进程管理 ----------
def find_recorder_pids() -> list:
    """扫描 /proc, 查找项目目录下正在运行的 main.py 录制进程。"""
    pids = []
    project_real = os.path.realpath(BASE_DIR)
    if not os.path.isdir('/proc'):
        return pids
    for name in os.listdir('/proc'):
        if not name.isdigit():
            continue
        try:
            with open(f'/proc/{name}/cmdline', 'rb') as f:
                raw = f.read().decode('utf-8', errors='ignore')
            if not any('main.py' in arg for arg in raw.split('\0')):
                continue
            cwd = os.readlink(f'/proc/{name}/cwd')
            if os.path.realpath(cwd) != project_real and not os.path.realpath(cwd).startswith(project_real + os.sep):
                continue
        except (OSError, IOError):
            continue
        pids.append(int(name))
    return pids


def recorder_status() -> dict:
    pids = find_recorder_pids()
    status = {'running': bool(pids), 'pids': pids, 'uptime_seconds': None}
    if pids:
        try:
            with open('/proc/uptime') as f:
                sys_uptime = float(f.read().split()[0])
            with open(f'/proc/{pids[0]}/stat') as f:
                parts = f.read().rsplit(')', maxsplit=1)[-1].split()
            starttime_ticks = int(parts[19])
            ticks = os.sysconf('SC_CLK_TCK')
            status['uptime_seconds'] = max(0, int(sys_uptime - starttime_ticks / ticks))
        except Exception:
            pass
    return status


def start_recorder():
    if find_recorder_pids():
        return True, '录制进程已在运行'
    log_path = os.path.join(BASE_DIR, 'logs', 'recorder.log')
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    try:
        log_fh = open(log_path, 'ab')
    except OSError as exc:
        return False, str(exc)
    env = dict(os.environ)
    env['PYTHONUNBUFFERED'] = '1'
    try:
        proc = subprocess.Popen(
            [sys.executable, os.path.join(BASE_DIR, 'main.py')],
            cwd=BASE_DIR, stdout=log_fh, stderr=subprocess.STDOUT,
            env=env, start_new_session=True,
        )
    except OSError as exc:
        log_fh.close()
        return False, str(exc)
    log_fh.close()
    return True, f'录制进程已启动 (PID {proc.pid})'


def stop_recorder():
    pids = find_recorder_pids()
    if not pids:
        return True, '录制进程未在运行'
    for pid in pids:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    time.sleep(4)
    for pid in pids:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    return True, '录制进程已停止'


def read_recorder_log(tail_lines: int = 200) -> str:
    log_path = os.path.join(BASE_DIR, 'logs', 'recorder.log')
    if not os.path.exists(log_path):
        return ''
    try:
        with open(log_path, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 256 * 1024))
            data = f.read().decode('utf-8', errors='replace')
        return '\n'.join(data.splitlines()[-tail_lines:])
    except OSError:
        return ''


def maybe_auto_start() -> None:
    if AUTO_START_RECORDER:
        time.sleep(2)
        ok, msg = start_recorder()
        logger.info(f'自动开始录制: {ok} {msg}')


def compute_usage():
    used = 0
    count = 0
    for root, dirs, files in os.walk(VIDEO_ROOT):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for name in files:
            if name.startswith('.'):
                continue
            try:
                used += os.path.getsize(os.path.join(root, name))
                count += 1
            except OSError:
                pass
    total_disk = used
    try:
        total_disk = shutil.disk_usage(VIDEO_ROOT).total
    except OSError:
        pass
    return total_disk, used, count


def cleanup_empty_dirs(root: str) -> None:
    for current, dirs, _files in os.walk(root, topdown=False):
        for d in dirs:
            p = os.path.join(current, d)
            try:
                if not os.listdir(p):
                    os.rmdir(p)
            except OSError:
                pass


def enforce_storage_policy() -> None:
    """存储策略: 删除超过保留天数的文件; 若超过配额则删除最旧文件。"""
    now = time.time()
    cutoff = now - RETENTION_DAYS * 86400

    files = []
    for root, dirs, names in os.walk(VIDEO_ROOT):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for name in names:
            if name.startswith('.'):
                continue
            path = os.path.join(root, name)
            try:
                stat = os.stat(path)
            except OSError:
                continue
            files.append([path, stat.st_size, stat.st_mtime])

    # 1) 过期清理
    for item in files:
        path, _size, mtime = item
        if mtime < cutoff:
            try:
                os.remove(path)
                logger.info(f'存储管理: 删除过期文件 {path}')
            except OSError as exc:
                logger.error(f'存储管理: 删除文件失败 {path}: {exc}')

    # 2) 配额清理 (删除最旧文件, 跳过 1 小时内可能仍在录制的文件)
    remaining = [item for item in files if os.path.exists(item[0])]
    total_size = sum(item[1] for item in remaining)
    if total_size > QUOTA_BYTES:
        remaining.sort(key=lambda item: item[2])
        target = int(QUOTA_BYTES * 0.95)
        for item in remaining:
            if total_size <= target:
                break
            path, size, mtime = item
            if now - mtime < 3600:
                continue
            try:
                os.remove(path)
                total_size -= size
                logger.info(f'存储管理: 空间超限, 删除最旧文件 {path}')
            except OSError as exc:
                logger.error(f'存储管理: 删除文件失败 {path}: {exc}')

    cleanup_empty_dirs(VIDEO_ROOT)


def storage_manager_loop() -> None:
    time.sleep(60)
    while True:
        try:
            enforce_storage_policy()
        except Exception as exc:
            logger.error(f'存储管理线程异常: {exc}')
        time.sleep(600)


class Handler(BaseHTTPRequestHandler):
    server_version = 'DouyinLiveRecorderWeb/1.0'

    def log_message(self, fmt: str, *args) -> None:
        logger.debug('web access: ' + fmt % args)

    # ---------- 基础响应 ----------
    def send_json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self):
        try:
            length = int(self.headers.get('Content-Length', 0) or 0)
            raw = self.rfile.read(length) if length else b''
            return json.loads(raw.decode('utf-8')) if raw else {}
        except Exception:
            return None

    # ---------- 登录 / 会话 ----------
    def _cookies(self) -> dict:
        header = self.headers.get('Cookie') or ''
        cookies = {}
        for part in header.split(';'):
            if '=' in part:
                key, _, value = part.strip().partition('=')
                cookies[key] = value
        return cookies

    def _session(self):
        token = self._cookies().get('session')
        if not token:
            return None
        with SESSIONS_LOCK:
            sess = SESSIONS.get(token)
            if sess and sess['expires'] > time.time():
                return sess
            if sess:
                SESSIONS.pop(token, None)
        return None

    def _set_session_cookie(self, token: str) -> None:
        self.send_header('Set-Cookie', f'session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}')

    def _clear_session_cookie(self) -> None:
        self.send_header('Set-Cookie', 'session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0')

    def handle_login(self) -> None:
        data = self.read_json_body() or {}
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''
        if username == ADMIN_USER and password == ADMIN_PASSWORD:
            role = 'admin'
        elif username:
            role = 'guest'
        else:
            self.send_json({'error': '请输入用户名'}, 400)
            return
        token = secrets.token_hex(32)
        with SESSIONS_LOCK:
            SESSIONS[token] = {'role': role, 'name': username, 'expires': time.time() + SESSION_TTL}
        body = json.dumps({'ok': True, 'role': role, 'name': username}, ensure_ascii=False).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self._set_session_cookie(token)
        self.end_headers()
        self.wfile.write(body)

    def handle_logout(self) -> None:
        token = self._cookies().get('session')
        if token:
            with SESSIONS_LOCK:
                SESSIONS.pop(token, None)
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self._clear_session_cookie()
        self.end_headers()
        self.wfile.write(body)

    def handle_me(self) -> None:
        sess = self._session()
        if not sess:
            self.send_json({'authenticated': False}, 401)
            return
        self.send_json({'authenticated': True, 'role': sess['role'], 'name': sess['name']})

    # ---------- 静态页面 ----------
    def serve_webui(self) -> None:
        index_path = os.path.join(WEBUI_DIR, 'index.html')
        if not os.path.isfile(index_path):
            self.send_json({'error': 'webui/index.html not found'}, 500)
            return
        try:
            with open(index_path, 'rb') as f:
                body = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError as exc:
            self.send_json({'error': str(exc)}, 500)

    # ---------- 文件流 ----------
    def _parse_range(self, size: int):
        header = self.headers.get('Range')
        if not header:
            return 0, size - 1, size
        match = re.match(r'bytes=(\d*)-(\d*)', header.strip())
        if not match:
            return None, None, None
        start_s, end_s = match.groups()
        if start_s == '':
            suffix = int(end_s)
            start = max(0, size - suffix)
            end = size - 1
        else:
            start = int(start_s)
            end = int(end_s) if end_s else size - 1
        if start >= size:
            return None, None, None
        end = min(end, size - 1)
        return start, end, end - start + 1

    def stream_file(self, path: str, download: bool = False, filename: str | None = None) -> None:
        try:
            size = os.path.getsize(path)
        except OSError:
            self.send_json({'error': '文件不存在'}, 404)
            return

        start, end, length = self._parse_range(size)
        ctype = content_type(path)
        fname = filename or os.path.basename(path)

        if start is None:
            self.send_response(416)
            self.send_header('Content-Range', f'bytes */{size}')
            self.end_headers()
            return

        status = 206 if (start != 0 or end != size - 1) else 200
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Accept-Ranges', 'bytes')
        if download:
            ascii_name = ''.join(
                c if 32 <= ord(c) < 127 and c not in '"\\' else '_' for c in fname
            ).strip() or 'download'
            self.send_header(
                'Content-Disposition',
                f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{urllib.parse.quote(fname)}"
            )
        if status == 206:
            self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
        self.send_header('Content-Length', str(length))
        self.end_headers()

        if self.command == 'HEAD':
            return

        try:
            with open(path, 'rb') as f:
                f.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = f.read(min(1024 * 256, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (OSError, ConnectionError) as exc:
            logger.debug(f'流式传输中断: {exc}')

    # ---------- 接口 ----------
    def handle_videos(self) -> None:
        items = []
        for root, dirs, files in os.walk(VIDEO_ROOT):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for name in files:
                if name.startswith('.'):
                    continue
                path = os.path.join(root, name)
                try:
                    stat = os.stat(path)
                except OSError:
                    continue
                rel = os.path.relpath(path, VIDEO_ROOT).replace(os.sep, '/')
                rel_dir = os.path.relpath(root, VIDEO_ROOT).replace(os.sep, '/')
                items.append({
                    'name': name,
                    'path': rel,
                    'dir': rel_dir,
                    'size': stat.st_size,
                    'mtime': stat.st_mtime,
                    'ext': os.path.splitext(name)[1].lstrip('.').lower(),
                })
        items.sort(key=lambda x: x['mtime'], reverse=True)
        self.send_json({'videos': items, 'count': len(items)})

    def handle_storage(self) -> None:
        total_disk, used, count = compute_usage()
        self.send_json({
            'video_root': VIDEO_ROOT,
            'quota_bytes': QUOTA_BYTES,
            'used_bytes': used,
            'total_disk_bytes': total_disk,
            'retention_days': RETENTION_DAYS,
            'file_count': count,
        })

    def handle_stream(self) -> None:
        rel = self.query.get('path', [''])[0]
        path = safe_path(rel)
        if not path or not os.path.isfile(path):
            self.send_json({'error': '非法路径'}, 400)
            return
        self.stream_file(path)

    def handle_download(self) -> None:
        rel = self.query.get('path', [''])[0]
        path = safe_path(rel)
        if not path or not os.path.isfile(path):
            self.send_json({'error': '非法路径'}, 400)
            return
        self.stream_file(path, download=True)

    def handle_playlist(self) -> None:
        rel = self.query.get('path', [''])[0]
        path = safe_path(rel)
        if not path or not os.path.isfile(path):
            self.send_json({'error': '非法路径'}, 400)
            return
        duration = get_duration(path) or 600.0
        duration = max(1.0, duration)
        stream_url = '/api/stream?path=' + urllib.parse.quote(rel, safe='')
        playlist = (
            '#EXTM3U\n'
            '#EXT-X-VERSION:3\n'
            f'#EXT-X-TARGETDURATION:{int(duration) + 1}\n'
            '#EXT-X-MEDIA-SEQUENCE:0\n'
            f'#EXTINF:{duration:.3f},\n'
            f'{stream_url}\n'
            '#EXT-X-ENDLIST\n'
        )
        body = playlist.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/vnd.apple.mpegurl')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def handle_segment(self) -> None:
        data = self.read_json_body()
        if not data:
            self.send_json({'error': '请求体无效'}, 400)
            return
        rel = data.get('path', '')
        path = safe_path(rel)
        if not path or not os.path.isfile(path):
            self.send_json({'error': '非法路径'}, 400)
            return
        try:
            start = float(data.get('start', 0))
            end = float(data.get('end', 0))
        except (TypeError, ValueError):
            self.send_json({'error': '起止时间无效'}, 400)
            return
        if end <= start:
            self.send_json({'error': '结束时间必须大于开始时间'}, 400)
            return
        fmt = data.get('format', 'mp4')
        if fmt not in ('mp4', 'ts'):
            fmt = 'mp4'
        duration = end - start

        base_name = os.path.splitext(os.path.basename(path))[0]
        out_name = f'{base_name}_clip_{int(start)}-{int(end)}.{fmt}'
        tmp_dir = tempfile.mkdtemp(prefix='dlr_clip_')
        out_path = os.path.join(tmp_dir, out_name)

        command = [
            'ffmpeg', '-y',
            '-ss', str(start),
            '-i', path,
            '-t', str(duration),
            '-c', 'copy',
            '-avoid_negative_ts', 'make_zero',
        ]
        if fmt == 'mp4':
            command += ['-movflags', '+faststart', '-f', 'mp4']
        else:
            command += ['-f', 'mpegts']
        command += [out_path]

        try:
            subprocess.run(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                timeout=1800, check=False
            )
            if not os.path.isfile(out_path) or os.path.getsize(out_path) == 0:
                self.send_json({'error': '片段生成失败'}, 500)
                return
            self.stream_file(out_path, download=True, filename=out_name)
        except subprocess.TimeoutExpired:
            self.send_json({'error': '片段生成超时'}, 500)
        except Exception as exc:
            logger.error(f'片段生成失败: {exc}')
            self.send_json({'error': f'片段生成失败: {exc}'}, 500)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def handle_delete(self) -> None:
        data = self.read_json_body()
        if not data:
            self.send_json({'error': '请求体无效'}, 400)
            return
        rel = data.get('path', '')
        code = (data.get('code') or '').strip()

        if DELETE_REQUIRES_TOTP and TOTP_SECRET:
            if not code:
                self.send_json({'error': '请输入动态码', 'need_code': True}, 403)
                return
            if not totp_verify(TOTP_SECRET, code):
                self.send_json({'error': '动态码错误或已过期', 'need_code': True}, 403)
                return

        path = safe_path(rel)
        if path is None:
            self.send_json({'error': '非法路径'}, 400)
            return
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            elif os.path.isfile(path):
                os.remove(path)
            else:
                self.send_json({'error': '文件不存在'}, 404)
                return
        except OSError as exc:
            self.send_json({'error': f'删除失败: {exc}'}, 500)
            return
        logger.info(f'网页管理: 已删除 {path}')
        self.send_json({'ok': True})

    def handle_totp_status(self) -> None:
        self.send_json({
            'enabled': DELETE_REQUIRES_TOTP,
            'has_secret': bool(TOTP_SECRET),
        })

    def handle_totp_setup(self) -> None:
        if not TOTP_SECRET:
            self.send_json({'error': '未配置动态码密钥'}, 500)
            return
        uri = provisioning_uri(TOTP_SECRET, 'DouyinLiveRecorder', 'DouyinLiveRecorder')
        self.send_json({'secret': TOTP_SECRET, 'uri': uri})

    def handle_totp_qr(self) -> None:
        if not TOTP_SECRET:
            self.send_json({'error': '未配置动态码密钥'}, 500)
            return
        uri = provisioning_uri(TOTP_SECRET, 'DouyinLiveRecorder', 'DouyinLiveRecorder')
        try:
            import segno
            import io
            buf = io.BytesIO()
            segno.make(uri, error='m').save(buf, kind='svg', scale=6, border=2)
            body = buf.getvalue()
            self.send_response(200)
            self.send_header('Content-Type', 'image/svg+xml; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except ImportError:
            self.send_json({'error': '未安装 segno 库, 请手动输入密钥'}, 501)

    def handle_recorder_status(self) -> None:
        status = recorder_status()
        status['auto_start'] = AUTO_START_RECORDER
        self.send_json(status)

    def handle_recorder_start(self) -> None:
        ok, msg = start_recorder()
        self.send_json({'ok': ok, 'message': msg})

    def handle_recorder_stop(self) -> None:
        ok, msg = stop_recorder()
        self.send_json({'ok': ok, 'message': msg})

    def handle_recorder_log(self) -> None:
        try:
            tail = int(self.query.get('lines', ['200'])[0] or 200)
        except ValueError:
            tail = 200
        self.send_json({'log': read_recorder_log(tail)})

    # ---------- 路由 ----------
    def _route(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        pathname = parsed.path.rstrip('/') or '/'
        self.query = urllib.parse.parse_qs(parsed.query)

        # 公开接口 (无需登录)
        if self.command == 'GET' and pathname in ('/', '/index.html'):
            return self.serve_webui()
        if self.command == 'GET' and pathname == '/api/me':
            return self.handle_me()
        if self.command == 'POST' and pathname == '/api/login':
            return self.handle_login()
        if self.command == 'POST' and pathname == '/api/logout':
            return self.handle_logout()

        # 以下接口需要登录
        session = self._session()
        if not session:
            return self.send_json({'error': '未登录', 'authenticated': False}, 401)
        is_admin = session['role'] == 'admin'

        if self.command == 'GET':
            if pathname == '/api/videos':
                return self.handle_videos()
            if pathname == '/api/storage':
                return self.handle_storage()
            if pathname == '/api/stream':
                return self.handle_stream()
            if pathname == '/api/download':
                return self.handle_download()
            if pathname == '/api/playlist':
                return self.handle_playlist()
            if pathname == '/api/recorder/status':
                return self.handle_recorder_status()
            if pathname == '/api/recorder/log':
                if not is_admin:
                    return self.send_json({'error': '需要管理员权限'}, 403)
                return self.handle_recorder_log()
            if pathname == '/api/totp/status':
                if not is_admin:
                    return self.send_json({'error': '需要管理员权限'}, 403)
                return self.handle_totp_status()
            if pathname == '/api/totp/setup':
                if not is_admin:
                    return self.send_json({'error': '需要管理员权限'}, 403)
                return self.handle_totp_setup()
            if pathname == '/api/totp/qr':
                if not is_admin:
                    return self.send_json({'error': '需要管理员权限'}, 403)
                return self.handle_totp_qr()
        elif self.command == 'POST':
            if pathname == '/api/segment':
                return self.handle_segment()
            if pathname == '/api/delete':
                if not is_admin:
                    return self.send_json({'error': '需要管理员权限'}, 403)
                return self.handle_delete()
            if pathname == '/api/recorder/start':
                if not is_admin:
                    return self.send_json({'error': '需要管理员权限'}, 403)
                return self.handle_recorder_start()
            if pathname == '/api/recorder/stop':
                if not is_admin:
                    return self.send_json({'error': '需要管理员权限'}, 403)
                return self.handle_recorder_stop()
        self.send_json({'error': 'not found'}, 404)

    def do_GET(self) -> None:
        try:
            self._route()
        except (ConnectionError, BrokenPipeError):
            pass
        except Exception as exc:
            logger.error(f'请求处理异常: {exc}')
            try:
                self.send_json({'error': 'internal error'}, 500)
            except Exception:
                pass

    def do_POST(self) -> None:
        self.do_GET()


def start_web_server() -> bool:
    """启动网页管理服务(非阻塞), 返回是否已启动。由 web_server.py 独立运行。"""
    global _server_started
    with _server_lock:
        if _server_started:
            return False
        load_config()
        if not WEB_ENABLED:
            logger.info('网页管理服务未开启(配置: 网页服务.是否开启网页服务)')
            return False
        try:
            server = ThreadingHTTPServer((HOST, PORT), Handler)
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            threading.Thread(target=storage_manager_loop, daemon=True).start()
            threading.Thread(target=maybe_auto_start, daemon=True).start()
        except OSError as exc:
            logger.error(f'网页管理服务启动失败(端口 {PORT} 可能被占用): {exc}')
            return False
        _server_started = True
        logger.info(f'网页管理服务已启动: http://{HOST}:{PORT}  视频目录: {VIDEO_ROOT}')
        logger.info(f'存储配额: {QUOTA_BYTES / 1024 ** 3:.0f}GB, 保留天数: {RETENTION_DAYS}')
        return True


def main() -> None:
    if not start_web_server():
        return
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
