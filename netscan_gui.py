#!/usr/bin/env python3
"""
NetScan GUI v2.1 — визуализация структуры IP-сети.
Windows 10/11, PySide6. Исправления помечены '# FIX #N'.
"""
import sys, os, csv, json, math, sqlite3, ipaddress, socket, subprocess, time, ctypes
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal, QTimer, QPointF, QRectF, QObject
from PySide6.QtGui import (QColor, QPen, QBrush, QFont, QAction, QPainter,
                            QImage, QLinearGradient, QPolygonF, QIcon, QPixmap)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QPushButton, QLineEdit, QLabel, QTableWidget, QTableWidgetItem, QSplitter,
    QGraphicsView, QGraphicsScene, QGraphicsItem, QGraphicsPolygonItem,
    QGraphicsLineItem, QGraphicsTextItem, QMessageBox, QFileDialog, QStatusBar,
    QToolBar, QProgressBar, QSpinBox, QGroupBox, QHeaderView,
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QTextEdit, QListWidget, QListWidgetItem
)

IS_WIN = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000 if IS_WIN else 0
FROZEN = getattr(sys, "frozen", False)
BASE_DIR = Path(os.path.dirname(sys.executable if FROZEN else os.path.abspath(__file__)))


# FIX #4: если папка с EXE не для записи — пишем в LOCALAPPDATA
def _resolve_db_path() -> Path:
    candidates = [BASE_DIR]
    if IS_WIN:
        la = os.environ.get("LOCALAPPDATA")
        if la:
            candidates.append(Path(la) / "NetScanGUI")
    else:
        candidates.append(Path.home() / ".local" / "share" / "NetScanGUI")
    for d in candidates:
        try:
            d.mkdir(parents=True, exist_ok=True)
            test = d / ".wtest"
            test.write_text("x"); test.unlink()
            return d / "netscan_history.db"
        except Exception:
            continue
    return Path.cwd() / "netscan_history.db"

DB_PATH = _resolve_db_path()


# ==================== ADMIN ====================

def is_admin() -> bool:
    if not IS_WIN:
        try: return os.geteuid() == 0
        except Exception: return False
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception: return False


def elevate_and_exit():
    if not IS_WIN: return
    params = " ".join(f'"{a}"' if " " in a else a for a in sys.argv[1:])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    except Exception:
        pass
    sys.exit(0)


# ==================== OUI ====================

OUI = {
    "00:50:56": "VMware",       "00:0C:29": "VMware",
    "08:00:27": "VirtualBox",   "52:54:00": "QEMU/KVM",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:1A:2B": "Intel",        "00:1B:21": "Intel",       "34:13:E8": "Intel",
    "00:1E:C2": "Apple",        "3C:07:54": "Apple",       "F0:18:98": "Apple",
    "B0:BE:76": "TP-Link",      "50:C7:BF": "TP-Link",     "A4:2B:B0": "TP-Link",
    "C4:6E:1F": "TP-Link",      "E8:94:F6": "TP-Link",     "60:32:B1": "TP-Link",
    "00:1E:58": "D-Link",       "1C:7E:E5": "D-Link",      "00:22:B0": "D-Link",
    "00:1F:33": "Netgear",      "20:4E:7F": "Netgear",     "A0:40:A0": "Netgear",
    "00:14:6C": "Netgear",      "28:C6:8E": "Netgear",
    "00:1D:7E": "Cisco-Linksys","C0:C1:C0": "Cisco-Linksys",
    "00:1A:70": "Cisco",        "00:1B:54": "Cisco",       "00:24:97": "Cisco",
    "00:00:0C": "Cisco",
    "00:11:32": "Synology",     "00:08:9B": "QNAP",
    "00:16:6C": "Samsung",      "34:23:BA": "Samsung",     "40:0E:85": "Samsung",
    "78:1F:DB": "Samsung",      "00:1A:8A": "Samsung",
    "3C:D9:2B": "HP",           "10:60:4B": "HP",          "00:1E:0B": "HP",
    "00:25:B3": "HP",           "00:1B:78": "HP",          "28:80:23": "HP",
    "B8:AE:ED": "Espressif",    "24:0A:C4": "Espressif",   "84:F3:EB": "Espressif",
    "DC:4F:22": "Espressif",    "30:AE:A4": "Espressif",
    "00:17:88": "Philips Hue",  "18:B4:30": "Nest",
    "44:65:0D": "Amazon",       "68:54:FD": "Amazon",      "74:C2:46": "Amazon",
    "00:04:20": "Sonos",        "48:A6:B8": "Sonos",
}

def get_vendor(mac: str) -> str:
    if not mac or len(mac) < 8: return ""
    return OUI.get(mac[:8].upper(), "")


DEVICE_TYPES = {
    "gateway":    ("Шлюз",            "#ffb74d", "#e65100"),
    "router":     ("Роутер",          "#ff8a65", "#bf360c"),
    "server":     ("Сервер",          "#ba68c8", "#4a148c"),
    "windows-pc": ("Windows-ПК",      "#64b5f6", "#0d47a1"),
    "linux-pc":   ("Linux-ПК",        "#4db6ac", "#004d40"),
    "printer":    ("Принтер",         "#90a4ae", "#37474f"),
    "nas":        ("NAS",             "#81c784", "#1b5e20"),
    "iot":        ("IoT-устройство",  "#ffd54f", "#ff6f00"),
    "mobile":     ("Мобильное",       "#f48fb1", "#880e4f"),
    "web-device": ("Веб-устройство",  "#4fc3f7", "#01579b"),
    "unknown":    ("Неизвестно",      "#b0bec5", "#455a64"),
}


def classify_device(host, is_gateway=False) -> str:
    if is_gateway: return "gateway"
    ports = set(host.open_ports)
    hn = (host.hostname or "").lower()
    vendor = get_vendor(host.mac).lower()

    if ports & {9100, 515, 631}: return "printer"
    if "synology" in vendor or "qnap" in vendor or ports & {5000, 5001}: return "nas"
    if ports & {3306, 5432, 27017, 6379, 1433}: return "server"
    if "srv-" in hn or "server" in hn or "-db" in hn: return "server"
    if 3389 in ports or (ports & {135, 139, 445} and "windows" in host.os_guess.lower()):
        return "windows-pc"
    if 22 in ports and "windows" not in host.os_guess.lower(): return "linux-pc"
    if ports & {1883, 8883}: return "iot"
    if any(k in hn for k in ("esp", "iot", "shelly", "tasmota", "sonoff", "smart")): return "iot"
    if "espressif" in vendor or "philips" in vendor or "amazon" in vendor or "nest" in vendor: return "iot"
    if any(k in hn for k in ("iphone", "ipad", "android", "pixel", "-mob")): return "mobile"
    if vendor in ("apple", "samsung", "xiaomi", "huawei"): return "mobile"
    if ports & {80, 443, 8080, 8443} and not ports & {22, 3389}: return "web-device"
    if ports: return "server"
    return "unknown"


# ==================== NETWORK ====================

@dataclass
class Host:
    ip: str
    mac: str = ""
    hostname: str = ""
    ttl: int = 0
    os_guess: str = "unknown"
    open_ports: list = field(default_factory=list)
    rtt_ms: float = 0.0
    dev_type: str = "unknown"

    def to_row(self):
        name = DEVICE_TYPES.get(self.dev_type, ("?",))[0]
        return [self.ip, self.hostname or "—", self.mac or "—",
                get_vendor(self.mac) or "—",
                str(self.ttl or "—"), self.os_guess,
                ",".join(map(str, self.open_ports)) or "—",
                f"{self.rtt_ms:.1f}", name]

    def to_dict(self):
        d = asdict(self)
        d["open_ports"] = ",".join(map(str, self.open_ports))
        return d


# FIX #9: явный FileNotFoundError при отсутствии ping.exe
def ping_host(ip, timeout=1):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
    try:
        t0 = time.time()
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout + 2,
                           creationflags=CREATE_NO_WINDOW,
                           errors="ignore")
        rtt = (time.time() - t0) * 1000
        if r.returncode != 0:
            return False, 0.0, 0
        ttl = 0
        low = (r.stdout or "").lower()
        if "ttl=" in low:
            try: ttl = int(low.split("ttl=")[1].split()[0].strip(".,;"))
            except Exception: pass
        return True, rtt, ttl
    except FileNotFoundError:
        return False, 0.0, 0
    except Exception:
        return False, 0.0, 0


def guess_os(ttl):
    if ttl == 0: return "unknown"
    if ttl <= 64: return "Linux/Unix/Android"
    if ttl <= 128: return "Windows"
    return "Cisco/Network"


def scan_ports(ip, ports, timeout=0.4):
    opened = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, p)) == 0: opened.append(p)
        except Exception: pass
        finally: s.close()
    return opened


def resolve_hostname(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except Exception: return ""


def get_arp_table():
    table = {}
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                           creationflags=CREATE_NO_WINDOW, errors="ignore")
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].count(".") == 3 and "-" in parts[1]:
                mac = parts[1].replace("-", ":").upper()
                if mac != "FF:FF:FF:FF:FF:FF": table[parts[0]] = mac
    except Exception: pass
    return table


def get_default_gateway():
    try:
        r = subprocess.run(["ipconfig"], capture_output=True, text=True,
                           creationflags=CREATE_NO_WINDOW, errors="ignore")
        for line in (r.stdout or "").splitlines():
            low = line.lower()
            if ("основной шлюз" in low or "default gateway" in low) and ":" in line:
                ip = line.split(":")[-1].strip()
                if ip and ip[0].isdigit(): return ip
    except Exception: pass
    return ""


def detect_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close()
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except Exception:
        return "192.168.1.0/24"


# ==================== WORKERS ====================

class ScanWorker(QThread):
    host_found = Signal(object)
    progress = Signal(int, int, float)
    log = Signal(str)
    finished_scan = Signal()

    def __init__(self, subnet, ports, workers=64, timeout=1):
        super().__init__()
        self.subnet, self.ports = subnet, ports
        self.workers, self.timeout = workers, timeout
        self._stop = False

    def stop(self): self._stop = True

    def run(self):
        try:
            net = ipaddress.ip_network(self.subnet, strict=False)
        except Exception as e:
            self.log.emit(f"❌ Некорректная подсеть: {e}")
            self.finished_scan.emit(); return

        ips = [str(h) for h in net.hosts()]
        if len(ips) > 4096:
            self.log.emit(f"⚠ Слишком большая сеть — обрезаю до 4096")
            ips = ips[:4096]

        total = len(ips)
        self.log.emit(f"▶ Сканирование {self.subnet}: {total} адресов…")
        arp = get_arp_table()
        t_start = time.time()
        done = 0

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(ping_host, ip, self.timeout): ip for ip in ips}
            for fut in as_completed(futures):
                if self._stop:
                    self.log.emit("⏹ Сканирование остановлено.")
                    break
                ip = futures[fut]
                try: ok, rtt, ttl = fut.result()
                except Exception: ok = False; rtt = 0; ttl = 0
                if ok:
                    h = Host(ip=ip, rtt_ms=round(rtt, 1), ttl=ttl,
                             os_guess=guess_os(ttl))
                    h.mac = arp.get(ip, "")
                    h.hostname = resolve_hostname(ip)
                    h.open_ports = scan_ports(ip, self.ports)
                    h.dev_type = classify_device(h)
                    self.host_found.emit(h)
                done += 1
                elapsed = time.time() - t_start
                eta = (elapsed / done) * (total - done) if done else 0
                self.progress.emit(done, total, eta)

        self.finished_scan.emit()


# FIX #2: Lock вокруг self.ips
class MonitorWorker(QThread):
    status = Signal(str, bool, float)

    def __init__(self, interval=10, timeout=1, workers=48):
        super().__init__()
        self._ips: list = []
        self._lock = threading.Lock()
        self.interval = interval
        self.timeout = timeout
        self.workers = workers
        self._stop = False

    def stop(self):
        self._stop = True

    def set_ips(self, ips):
        with self._lock:
            self._ips = list(ips)

    def _snapshot(self):
        with self._lock:
            return list(self._ips)

    def run(self):
        while not self._stop:
            snapshot = self._snapshot()
            if snapshot:
                with ThreadPoolExecutor(max_workers=self.workers) as pool:
                    futures = {pool.submit(ping_host, ip, self.timeout): ip
                               for ip in snapshot}
                    for f in as_completed(futures):
                        if self._stop: break
                        ip = futures[f]
                        try: ok, rtt, _ = f.result()
                        except Exception: ok, rtt = False, 0.0
                        self.status.emit(ip, ok, rtt)
            for _ in range(int(self.interval * 10)):
                if self._stop: break
                time.sleep(0.1)


# ==================== GRAPH ====================

class NodeItem(QGraphicsPolygonItem):
    # FIX #6: атрибуты выставляются ПОСЛЕ super().__init__()
    def __init__(self, host, dev_type="unknown", is_gateway=False):
        size = 76 if is_gateway else 56
        poly = self._make_shape(dev_type, size)
        super().__init__(poly)

        self.dev_type = dev_type
        self.is_gateway = is_gateway
        self.host = host
        self.edges = []
        self.alive = True

        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setZValue(1)
        self.setAcceptHoverEvents(True)

        top, bot = DEVICE_TYPES.get(dev_type, DEVICE_TYPES["unknown"])[1:3]
        grad = QLinearGradient(-size/2, -size/2, size/2, size/2)
        grad.setColorAt(0, QColor(top))
        grad.setColorAt(1, QColor(bot))
        self.setBrush(QBrush(grad))
        self.setPen(QPen(QColor("#0d0d1a"), 2))

        label = "GW" if is_gateway else (host.ip.split(".")[-1] if host else "")
        self.text = QGraphicsTextItem(label, self)
        self.text.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self._apply_text_color(is_gateway)
        br = self.text.boundingRect()
        self.text.setPos(-br.width()/2, -br.height()/2)

        self._refresh_tooltip()

    def _apply_text_color(self, is_gateway):
        # FIX #8: цвет текста зависит от фона узла
        if is_gateway:
            self.text.setDefaultTextColor(QColor("#1a1a1a"))
        else:
            self.text.setDefaultTextColor(QColor("white"))

    @staticmethod
    def _make_shape(t, size):
        r = size / 2
        if t == "gateway":
            return QPolygonF([QPointF(0,-r), QPointF(r,0), QPointF(0,r), QPointF(-r,0)])
        if t == "server":
            return QPolygonF([QPointF(r*math.cos(a + math.pi/2),
                                       r*math.sin(a + math.pi/2))
                              for a in [i*math.pi/3 for i in range(6)]])
        if t == "printer":
            r2 = r * 0.92
            return QPolygonF([QPointF(-r2,-r2), QPointF(r2,-r2),
                              QPointF(r2,r2), QPointF(-r2,r2)])
        if t == "iot":
            return QPolygonF([QPointF(0,-r), QPointF(r*0.87, r*0.5),
                              QPointF(-r*0.87, r*0.5)])
        if t == "nas":
            return QPolygonF([QPointF(0,-r), QPointF(r,0), QPointF(r,r),
                              QPointF(-r,r), QPointF(-r,0)])
        return QPolygonF([QPointF(r*math.cos(2*math.pi*i/24),
                                  r*math.sin(2*math.pi*i/24))
                          for i in range(24)])

    def _refresh_tooltip(self):
        if self.is_gateway:
            self.setToolTip("Шлюз по умолчанию"); return
        h = self.host
        dev_name = DEVICE_TYPES.get(self.dev_type, DEVICE_TYPES["unknown"])[0]
        self.setToolTip(
            f"<b>{dev_name}</b><br>"
            f"IP: <b>{h.ip}</b><br>"
            f"Host: {h.hostname or '—'}<br>"
            f"MAC: {h.mac or '—'}<br>"
            f"Вендор: {get_vendor(h.mac) or '—'}<br>"
            f"ОС: {h.os_guess}<br>"
            f"TTL: {h.ttl}<br>"
            f"RTT: {h.rtt_ms} мс<br>"
            f"Порты: {','.join(map(str, h.open_ports)) or '—'}")

    def set_alive(self, ok, rtt=0.0):
        self.alive = ok
        self.setPen(QPen(QColor("#00e676" if ok else "#ff1744"), 3 if not ok else 2))
        if ok and self.host: self.host.rtt_ms = round(rtt, 1)
        self._refresh_tooltip()

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for e in self.edges: e.update_position()
        return super().itemChange(change, value)


class EdgeItem(QGraphicsLineItem):
    def __init__(self, src, dst):
        super().__init__()
        self.src, self.dst = src, dst
        self.setPen(QPen(QColor("#90a4ae"), 1.4))
        self.setZValue(0)
        src.edges.append(self); dst.edges.append(self)
        self.update_position()

    def update_position(self):
        self.setLine(self.src.pos().x(), self.src.pos().y(),
                     self.dst.pos().x(), self.dst.pos().y())


class NetworkScene(QGraphicsScene):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.nodes: dict = {}
        self.edges: list = []
        self.gateway_node = None
        self._bg = QColor("#1e1e2e")
        self.setBackgroundBrush(QBrush(self._bg))

    def set_theme_bg(self, dark: bool):
        self._bg = QColor("#1e1e2e") if dark else QColor("#f5f5f8")
        self.setBackgroundBrush(QBrush(self._bg))

    def reset(self):
        self.clear()
        self.nodes.clear(); self.edges.clear()
        self.gateway_node = None

    def set_gateway(self, ip_label=""):
        self.gateway_node = NodeItem(None, "gateway", is_gateway=True)
        self.gateway_node.setPos(0, 0)
        self.addItem(self.gateway_node)

    def add_host(self, host):
        if self.gateway_node is None: self.set_gateway()
        node = NodeItem(host, host.dev_type)
        self.addItem(node)
        edge = EdgeItem(self.gateway_node, node)
        self.addItem(edge); self.edges.append(edge)
        self.nodes[host.ip] = node
        self._relayout()

    def _relayout(self):
        n = len(self.nodes)
        if n == 0 or not self.gateway_node: return
        r1 = 220
        for i, node in enumerate(self.nodes.values()):
            a = 2 * math.pi * i / max(n, 1) - math.pi/2
            r = r1 if n <= 12 else r1 + (i // 12) * 160
            node.setPos(r*math.cos(a), r*math.sin(a))

    def positions(self):
        pos = {}
        if self.gateway_node:
            pos["__GW__"] = (self.gateway_node.x(), self.gateway_node.y())
        for ip, nd in self.nodes.items():
            pos[ip] = (nd.x(), nd.y())
        return pos

    def apply_positions(self, pos):
        if self.gateway_node and "__GW__" in pos:
            gx, gy = pos["__GW__"]; self.gateway_node.setPos(gx, gy)
        for ip, (x, y) in pos.items():
            if ip in self.nodes: self.nodes[ip].setPos(x, y)


class GraphView(QGraphicsView):
    def __init__(self, scene, parent=None):
        super().__init__(scene, parent)
        self.setRenderHints(QPainter.RenderHint.Antialiasing |
                            QPainter.RenderHint.TextAntialiasing |
                            QPainter.RenderHint.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self._zoom = 1.0

    def wheelEvent(self, event):
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            f = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
            self._zoom *= f
            if 0.15 < self._zoom < 6.0: self.scale(f, f)
            event.accept()
        else:
            super().wheelEvent(event)

    def fit_to_content(self):
        r = self.scene().itemsBoundingRect()
        if r.isValid():
            self.fitInView(r.adjusted(-70, -70, 70, 70),
                           Qt.AspectRatioMode.KeepAspectRatio)
            self._zoom = 1.0

    def reset_zoom(self):
        self.resetTransform(); self._zoom = 1.0


# ==================== DATABASE ====================

def db_init():
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, subnet TEXT, hosts INTEGER);
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER, ip TEXT, hostname TEXT, mac TEXT,
            vendor TEXT, ttl INTEGER, os TEXT, ports TEXT,
            dev_type TEXT, rtt REAL);
    """)
    con.commit(); con.close()


def db_save_scan(subnet, hosts):
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("INSERT INTO scans(ts,subnet,hosts) VALUES(?,?,?)",
                    (datetime.now().isoformat(timespec="seconds"), subnet, len(hosts)))
        sid = cur.lastrowid
        for h in hosts:
            cur.execute("""INSERT INTO hosts(scan_id,ip,hostname,mac,vendor,ttl,os,
                           ports,dev_type,rtt) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                        (sid, h.ip, h.hostname, h.mac, get_vendor(h.mac), h.ttl,
                         h.os_guess, ",".join(map(str, h.open_ports)),
                         h.dev_type, h.rtt_ms))
        con.commit(); con.close()
        return sid
    except Exception:
        return None


def db_list_scans(limit=100):
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.execute("SELECT id,ts,subnet,hosts FROM scans "
                          "ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall(); con.close()
        return rows
    except Exception:
        return []


# ==================== STYLES ====================

DARK_QSS = """
QMainWindow,QWidget{background:#1e1e2e;color:#e0e0e0;}
QGroupBox{border:1px solid #3a3a52;border-radius:4px;margin-top:8px;
padding-top:8px;font-weight:bold;}
QGroupBox::title{subcontrol-origin:margin;left:10px;padding:0 4px;color:#64b5f6;}
QLineEdit,QComboBox,QSpinBox{background:#252537;color:#e0e0e0;
border:1px solid #3a3a52;border-radius:3px;padding:5px;}
QLineEdit:focus,QComboBox:focus{border:1px solid #1976d2;}
QLabel{color:#c0c0d0;}
QPushButton{background:#2e2e42;color:#e0e0e0;border:1px solid #3a3a52;
border-radius:3px;padding:6px 12px;}
QPushButton:hover{background:#3a3a52;}
QTableWidget{background:#252537;color:#e0e0e0;alternate-background-color:#2e2e42;
gridline-color:#3a3a52;}
QHeaderView::section{background:#1565c0;color:white;padding:4px;border:0;}
QStatusBar{background:#252537;color:#c0c0d0;}
QProgressBar{background:#1e1e2e;color:#e0e0e0;border:1px solid #3a3a52;
border-radius:3px;text-align:center;}
QProgressBar::chunk{background:#1976d2;border-radius:2px;}
QToolBar{background:#252537;spacing:4px;padding:2px;border:0;}
QToolButton{color:#e0e0e0;padding:6px 10px;background:transparent;border-radius:3px;}
QToolButton:hover{background:#3a3a52;}
QMenuBar{background:#252537;color:#e0e0e0;}
QMenuBar::item:selected{background:#3a3a52;}
QMenu{background:#252537;color:#e0e0e0;border:1px solid #3a3a52;}
QMenu::item:selected{background:#1976d2;}
QCheckBox{color:#c0c0d0;}
"""

LIGHT_QSS = """
QMainWindow,QWidget{background:#f5f5f8;color:#202030;}
QGroupBox{border:1px solid #c8c8d0;border-radius:4px;margin-top:8px;
padding-top:8px;font-weight:bold;}
QGroupBox::title{subcontrol-origin:margin;left:10px;padding:0 4px;color:#1565c0;}
QLineEdit,QComboBox,QSpinBox{background:white;color:#202030;
border:1px solid #c8c8d0;border-radius:3px;padding:5px;}
QLineEdit:focus{border:1px solid #1976d2;}
QLabel{color:#303040;}
QPushButton{background:#e8e8ee;color:#202030;border:1px solid #c8c8d0;
border-radius:3px;padding:6px 12px;}
QPushButton:hover{background:#d8d8e0;}
QTableWidget{background:white;color:#202030;alternate-background-color:#f0f0f5;
gridline-color:#d0d0d8;}
QHeaderView::section{background:#1976d2;color:white;padding:4px;border:0;}
QStatusBar{background:#e8e8ee;color:#404050;}
QProgressBar{background:#e8e8ee;color:#202030;border:1px solid #c8c8d0;
border-radius:3px;text-align:center;}
QProgressBar::chunk{background:#1976d2;border-radius:2px;}
QToolBar{background:#e8e8ee;spacing:4px;padding:2px;border:0;}
QToolButton{color:#202030;padding:6px 10px;background:transparent;border-radius:3px;}
QToolButton:hover{background:#d0d0d8;}
QMenuBar{background:#e8e8ee;color:#202030;}
QMenuBar::item:selected{background:#d0d0d8;}
QMenu{background:white;color:#202030;border:1px solid #c8c8d0;}
QMenu::item:selected{background:#1976d2;color:white;}
QCheckBox{color:#303040;}
"""


def make_app_icon() -> QIcon:
    pm = QPixmap(64, 64); pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm); p.setRenderHint(QPainter.RenderHint.Antialiasing)
    grad = QLinearGradient(0, 0, 64, 64)
    grad.setColorAt(0, QColor("#64b5f6")); grad.setColorAt(1, QColor("#0d47a1"))
    p.setBrush(QBrush(grad)); p.setPen(QPen(QColor("#0d47a1"), 2))
    p.drawEllipse(6, 6, 52, 52)
    p.setPen(QPen(QColor("white"), 2))
    p.drawLine(32, 12, 32, 32)
    p.drawLine(32, 32, 18, 48)
    p.drawLine(32, 32, 46, 48)
    p.setBrush(QBrush(QColor("#ffb74d")))
    p.drawEllipse(26, 8, 12, 12)
    p.drawEllipse(12, 44, 12, 12)
    p.drawEllipse(40, 44, 12, 12)
    p.end()
    return QIcon(pm)


# ==================== MAIN WINDOW ====================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetScan GUI v2.1 — структурное исследование IP-сети")
        self.resize(1450, 880)
        self.setWindowIcon(make_app_icon())

        db_init()
        self.worker = None
        self.monitor = None
        self.hosts = []
        self.dark_theme = True

        self._build_ui()
        self._build_menu()
        self._build_toolbar()
        self._build_statusbar()

        self.subnet_edit.setText(detect_local_subnet())
        self.gateway_ip = get_default_gateway()

        self._start_monitor()
        self._apply_theme(True)

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central); root.setContentsMargins(8, 8, 8, 8)

        params = QGroupBox("Параметры сканирования")
        form = QFormLayout(params)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self.subnet_edit = QLineEdit()
        self.subnet_edit.setPlaceholderText("192.168.1.0/24")
        form.addRow("Подсеть (CIDR):", self.subnet_edit)

        self.ports_edit = QLineEdit(
            "22,23,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5900,8080,8443,9100")
        form.addRow("TCP-порты:", self.ports_edit)

        row = QHBoxLayout()
        self.workers_spin = QSpinBox(); self.workers_spin.setRange(1, 512); self.workers_spin.setValue(64)
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(1, 10); self.timeout_spin.setValue(1)
        self.timeout_spin.setSuffix(" с")
        self.monitor_chk = QCheckBox("Мониторинг каждые")
        self.monitor_chk.setChecked(True)
        self.monitor_interval = QSpinBox(); self.monitor_interval.setRange(2, 120)
        self.monitor_interval.setValue(10); self.monitor_interval.setSuffix(" с")
        # FIX #3: чекбокс реально управляет мониторингом
        self.monitor_chk.toggled.connect(self._toggle_monitor)
        self.monitor_interval.valueChanged.connect(self._set_monitor_interval)
        row.addWidget(QLabel("Потоков:")); row.addWidget(self.workers_spin)
        row.addSpacing(12)
        row.addWidget(QLabel("Таймаут:")); row.addWidget(self.timeout_spin)
        row.addSpacing(12)
        row.addWidget(self.monitor_chk); row.addWidget(self.monitor_interval)
        row.addStretch()
        form.addRow("", self._wrap(row))

        self.btn_scan = QPushButton("▶  Начать сканирование")
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_scan.setStyleSheet(
            "QPushButton{background:#1976d2;color:white;font-weight:bold;"
            "padding:9px 18px;border-radius:4px;}"
            "QPushButton:hover{background:#1565c0;}"
            "QPushButton:disabled{background:#555;color:#aaa;}")

        self.btn_stop = QPushButton("■  Стоп")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_stop.setStyleSheet(
            "QPushButton{background:#c62828;color:white;font-weight:bold;"
            "padding:9px 18px;border-radius:4px;}"
            "QPushButton:hover{background:#b71c1c;}"
            "QPushButton:disabled{background:#555;color:#aaa;}")

        br = QHBoxLayout()
        br.addWidget(self.btn_scan); br.addWidget(self.btn_stop); br.addStretch()
        form.addRow("", self._wrap(br))
        root.addWidget(params)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left = QWidget(); lv = QVBoxLayout(left); lv.setContentsMargins(0,0,0,0)
        filt = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔍 Поиск: IP, hostname, MAC, вендор…")
        self.search_edit.textChanged.connect(self._apply_filter)
        self.type_filter = QComboBox()
        self.type_filter.addItem("Все типы", "all")
        for k, v in DEVICE_TYPES.items():
            if k != "gateway": self.type_filter.addItem(v[0], k)
        self.type_filter.currentIndexChanged.connect(self._apply_filter)
        filt.addWidget(self.search_edit, 1); filt.addWidget(self.type_filter)
        lv.addLayout(filt)

        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(
            ["IP", "Hostname", "MAC", "Вендор", "TTL", "ОС", "Порты", "RTT, мс", "Тип"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.doubleClicked.connect(self._on_table_dclick)
        self.table.itemSelectionChanged.connect(self._on_table_select)
        lv.addWidget(self.table)

        right = QWidget(); rv = QVBoxLayout(right); rv.setContentsMargins(0,0,0,0)
        rv.addWidget(QLabel("<b>Топология сети</b> · Ctrl+колесо — зум"))

        self.scene = NetworkScene(self)
        self.scene.setSceneRect(-1500, -1500, 3000, 3000)
        self.view = GraphView(self.scene)
        rv.addWidget(self.view, 1)

        gbtns = QHBoxLayout()
        for text, cb in [("⤢ По размеру", self.view.fit_to_content),
                         ("↺ Сброс зума", self.view.reset_zoom),
                         ("💾 PNG", self.export_png),
                         ("📄 CSV", self.export_csv),
                         ("🗂 Проект", self.save_project),
                         ("📚 История", self.show_history)]:
            b = QPushButton(text); b.clicked.connect(cb); gbtns.addWidget(b)
        gbtns.addStretch()
        rv.addLayout(gbtns)

        legend = QHBoxLayout()
        legend.addWidget(QLabel("<b>Легенда:</b>"))
        for key in ["gateway", "server", "windows-pc", "linux-pc",
                    "printer", "nas", "iot", "mobile"]:
            name, top, _ = DEVICE_TYPES[key]
            dot = QLabel(f'<span style="color:{top};font-size:18pt">●</span> {name}')
            legend.addWidget(dot)
        legend.addStretch()
        rv.addLayout(legend)

        splitter.addWidget(left); splitter.addWidget(right)
        splitter.setStretchFactor(0, 4); splitter.setStretchFactor(1, 6)
        splitter.setSizes([560, 860])
        root.addWidget(splitter, 1)

    def _wrap(self, layout):
        w = QWidget(); w.setLayout(layout); return w

    def _build_menu(self):
        mb = self.menuBar()
        m_file = mb.addMenu("&Файл")
        m_file.addAction("▶ Сканировать", self.start_scan, "F5")
        m_file.addAction("■ Остановить", self.stop_scan, "Esc")
        m_file.addSeparator()
        m_file.addAction("💾 Сохранить PNG…", self.export_png)
        m_file.addAction("📄 Экспорт CSV…", self.export_csv)
        m_file.addAction("🗂 Сохранить проект…", self.save_project, "Ctrl+S")
        m_file.addAction("📂 Открыть проект…", self.load_project, "Ctrl+O")
        m_file.addSeparator()
        m_file.addAction("📚 История сканирований…", self.show_history)
        m_file.addSeparator()
        m_file.addAction("Выход", self.close, "Ctrl+Q")

        m_view = mb.addMenu("&Вид")
        m_view.addAction("Тёмная тема", lambda: self._apply_theme(True))
        m_view.addAction("Светлая тема", lambda: self._apply_theme(False))
        m_view.addSeparator()
        m_view.addAction("⤢ По размеру", self.view.fit_to_content)
        m_view.addAction("↺ Сброс зума", self.view.reset_zoom)

        m_help = mb.addMenu("&Справка")
        m_help.addAction("ℹ О программе", self.about)

    def _build_toolbar(self):
        tb = QToolBar("Главная"); tb.setMovable(False)
        self.addToolBar(tb)
        for text, cb in [("▶ Сканировать", self.start_scan),
                         ("■ Стоп", self.stop_scan),
                         ("💾 PNG", self.export_png),
                         ("📄 CSV", self.export_csv),
                         ("🗂 Проект", self.save_project),
                         ("📂 Открыть", self.load_project),
                         ("📚 История", self.show_history),
                         ("🌓 Тема", lambda: self._apply_theme(not self.dark_theme))]:
            tb.addAction(text, cb)
        tb.addSeparator()
        tb.addAction("ℹ", self.about)

    def _build_statusbar(self):
        sb = QStatusBar(); self.setStatusBar(sb)
        self.status_lbl = QLabel("Готов к работе")
        sb.addWidget(self.status_lbl, 1)
        self.alive_lbl = QLabel("")
        self.progress = QProgressBar(); self.progress.setFixedWidth(280)
        sb.addPermanentWidget(self.alive_lbl)
        sb.addPermanentWidget(self.progress)

    def _apply_theme(self, dark: bool):
        self.dark_theme = dark
        self.setStyleSheet(DARK_QSS if dark else LIGHT_QSS)
        self.scene.set_theme_bg(dark)
        # FIX #8: перекраска текста узлов при смене темы
        for node in self.scene.nodes.values():
            node._apply_text_color(False)
        if self.scene.gateway_node:
            self.scene.gateway_node._apply_text_color(True)

    # ---------- Monitoring ----------

    def _start_monitor(self):
        self.monitor = MonitorWorker(interval=self.monitor_interval.value())
        self.monitor.status.connect(self._on_monitor_status)
        self.monitor.start()

    def _toggle_monitor(self, on: bool):
        # FIX #3: реальное включение/выключение мониторинга
        if not self.monitor: return
        if on:
            if not self.monitor.isRunning(): self.monitor.start()
            self.monitor_interval.setEnabled(True)
        else:
            self.monitor_interval.setEnabled(False)
            # просто останавливаем поток, узлы остаются "живыми" визуально
            self.monitor.set_ips([])

    def _set_monitor_interval(self, v: int):
        if self.monitor: self.monitor.interval = v

    def _on_monitor_status(self, ip, ok, rtt):
        node = self.scene.nodes.get(ip)
        if node: node.set_alive(ok, rtt)
        for r in range(self.table.rowCount()):
            item = self.table.item(r, 0)
            if item and item.text() == ip:
                it7 = self.table.item(r, 7)
                if it7:
                    it7.setText(f"{rtt:.1f}" if ok else "—")
                    it7.setForeground(QColor("#00e676") if ok else QColor("#ff5252"))
                break
        alive = sum(1 for n in self.scene.nodes.values() if n.alive)
        self.alive_lbl.setText(f"🟢 {alive}/{len(self.scene.nodes)} онлайн")

    # ---------- Scanning ----------

    def start_scan(self):
        if self.worker and self.worker.isRunning(): return
        subnet = self.subnet_edit.text().strip()
        try:
            ports = [int(p) for p in self.ports_edit.text().split(",") if p.strip()]
            if not ports: raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Ошибка", "Проверьте список портов."); return

        self.hosts.clear()
        self.table.setRowCount(0)
        self.scene.reset(); self.scene.set_gateway(self.gateway_ip)
        self.progress.setValue(0)

        self.btn_scan.setEnabled(False); self.btn_stop.setEnabled(True)
        self.status_lbl.setText(f"Сканирование {subnet}…")

        self.worker = ScanWorker(subnet, ports,
                                 workers=self.workers_spin.value(),
                                 timeout=self.timeout_spin.value())
        self.worker.host_found.connect(self._on_host_found)
        self.worker.progress.connect(self._on_progress)
        self.worker.log.connect(self.status_lbl.setText)
        self.worker.finished_scan.connect(self._on_finished)
        self.worker.start()

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop(); self.btn_stop.setEnabled(False)
            self.status_lbl.setText("Останавливаю…")

    def _on_host_found(self, host: Host):
        self.hosts.append(host)
        r = self.table.rowCount()
        self.table.insertRow(r)
        for c, val in enumerate(host.to_row()):
            item = QTableWidgetItem(str(val))
            if c == 0: item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
            if c == 8:
                item.setForeground(QColor(DEVICE_TYPES.get(host.dev_type,
                                                           ("", "#b0bec5"))[1]))
            self.table.setItem(r, c, item)
        self.scene.add_host(host)
        if self.monitor and self.monitor_chk.isChecked():
            self.monitor.set_ips([h.ip for h in self.hosts])

    def _on_progress(self, done, total, eta):
        pct = int(done * 100 / total) if total else 0
        eta_s = f"{int(eta)} с" if eta < 60 else f"{int(eta/60)} мин"
        self.progress.setValue(pct)
        self.progress.setFormat(f"{done}/{total} ({pct}%) — ETA {eta_s}")

    def _on_finished(self):
        self.btn_scan.setEnabled(True); self.btn_stop.setEnabled(False)
        self.view.fit_to_content()
        n = len(self.hosts)
        self.status_lbl.setText(f"✔ Готово. Устройств: {n}")
        self.progress.setValue(100); self.progress.setFormat(f"Найдено: {n}")
        if n: db_save_scan(self.subnet_edit.text().strip(), self.hosts)

    # ---------- Table interaction ----------

    def _on_table_select(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows: return
        ip = self.table.item(rows[0].row(), 0).text()
        node = self.scene.nodes.get(ip)
        if node:
            self.scene.clearSelection()
            node.setSelected(True)
            self.view.centerOn(node)

    def _on_table_dclick(self, index):
        # FIX #7: без дикого зума
        ip = self.table.item(index.row(), 0).text()
        node = self.scene.nodes.get(ip)
        if node:
            r = node.sceneBoundingRect().adjusted(-200, -200, 200, 200)
            self.view.fitInView(r, Qt.AspectRatioMode.KeepAspectRatio)
            self.view.centerOn(node)

    def _apply_filter(self):
        q = self.search_edit.text().strip().lower()
        t = self.type_filter.currentData()
        for r in range(self.table.rowCount()):
            row_match = True
            if q:
                row_match = any(
                    (self.table.item(r, c) and q in self.table.item(r, c).text().lower())
                    for c in range(self.table.columnCount()))
            type_match = True
            if t != "all":
                ip = self.table.item(r, 0).text()
                node = self.scene.nodes.get(ip)
                type_match = node and node.dev_type == t
            self.table.setRowHidden(r, not (row_match and type_match))
        for ip, node in self.scene.nodes.items():
            node.setVisible(t == "all" or node.dev_type == t)

    # ---------- Exports ----------

    def export_png(self):
        if not self.hosts:
            QMessageBox.information(self, "Пусто", "Сначала выполните сканирование."); return
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить PNG",
                                              str(BASE_DIR / "network.png"),
                                              "PNG (*.png)")
        if not path: return
        r = self.scene.itemsBoundingRect().adjusted(-50, -50, 50, 50)
        img = QImage(int(r.width()), int(r.height()),
                     QImage.Format.Format_ARGB32)
        img.fill(self.scene._bg)
        p = QPainter(img); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.scene.render(p, QRectF(img.rect()), r); p.end()
        img.save(path)
        self.status_lbl.setText(f"PNG: {path}")

    def export_csv(self):
        if not self.hosts:
            QMessageBox.information(self, "Пусто", "Сначала выполните сканирование."); return
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить CSV",
                                              str(BASE_DIR / "hosts.csv"),
                                              "CSV (*.csv)")
        if not path: return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["IP", "Hostname", "MAC", "Vendor", "TTL", "OS",
                        "Ports", "Type", "RTT_ms"])
            for h in self.hosts:
                w.writerow([h.ip, h.hostname, h.mac, get_vendor(h.mac),
                            h.ttl, h.os_guess, ",".join(map(str, h.open_ports)),
                            h.dev_type, h.rtt_ms])
        self.status_lbl.setText(f"CSV: {path}")

    def save_project(self):
        if not self.hosts:
            QMessageBox.information(self, "Пусто", "Нечего сохранять."); return
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить проект",
                                              str(BASE_DIR / "network.nsproj"),
                                              "NetScan Project (*.nsproj)")
        if not path: return
        data = {"version": 2,
                "saved": datetime.now().isoformat(timespec="seconds"),
                "subnet": self.subnet_edit.text().strip(),
                "hosts": [h.to_dict() for h in self.hosts],
                "positions": self.scene.positions()}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        self.status_lbl.setText(f"Проект: {path}")

    def load_project(self):
        path, _ = QFileDialog.getOpenFileName(self, "Открыть проект",
                                              str(BASE_DIR),
                                              "NetScan Project (*.nsproj)")
        if not path: return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось открыть: {e}"); return

        self.hosts.clear(); self.table.setRowCount(0)
        self.scene.reset(); self.scene.set_gateway(self.gateway_ip)
        self.subnet_edit.setText(data.get("subnet", ""))
        for hd in data.get("hosts", []):
            h = Host(ip=hd["ip"], mac=hd.get("mac", ""),
                     hostname=hd.get("hostname", ""),
                     ttl=hd.get("ttl", 0), os_guess=hd.get("os_guess", "unknown"),
                     open_ports=[int(p) for p in
                                 hd.get("open_ports", "").split(",") if p],
                     rtt_ms=hd.get("rtt_ms", 0.0),
                     dev_type=hd.get("dev_type", "unknown"))
            self._on_host_found(h)
        self.scene.apply_positions(data.get("positions", {}))
        self.status_lbl.setText(f"Загружено: {len(self.hosts)} устройств")

    def show_history(self):
        dlg = QDialog(self); dlg.setWindowTitle("История сканирований")
        dlg.resize(760, 480)
        v = QVBoxLayout(dlg)
        lst = QListWidget()
        for sid, ts, subnet, cnt in db_list_scans():
            QListWidgetItem(f"#{sid}  {ts}  {subnet}  — устройств: {cnt}", lst)
            lst.item(lst.count()-1).setData(Qt.ItemDataRole.UserRole, sid)
        v.addWidget(lst)
        info = QTextEdit(); info.setReadOnly(True)
        v.addWidget(info, 1)

        def on_select():
            it = lst.currentItem()
            if not it: return
            sid = it.data(Qt.ItemDataRole.UserRole)
            con = sqlite3.connect(DB_PATH)
            rows = con.execute(
                "SELECT ip,hostname,mac,vendor,ttl,os,ports,dev_type,rtt "
                "FROM hosts WHERE scan_id=? ORDER BY ip", (sid,)).fetchall()
            con.close()
            info.clear()
            info.append(f"<b>Скан #{sid}</b><br>")
            for r in rows:
                info.append(
                    f"<code>{r[0]:<15} {r[1] or '—':<25} {r[2] or '—':<18} "
                    f"{r[3] or '—':<15} TTL={r[4]} {r[7]}  "
                    f"[{r[6] or '—'}]  {r[8]} мс</code>")
        lst.currentItemChanged.connect(lambda *_: on_select())

        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(dlg.reject)
        v.addWidget(bb)
        dlg.exec()

    def about(self):
        QMessageBox.about(self, "О программе",
            "<h3>NetScan GUI v2.1</h3>"
            "<p>Визуализация структуры IP-сети и подключённых устройств.</p>"
            "<ul>"
            "<li>ICMP-сканирование и TCP-порт-скан</li>"
            "<li>Классификация устройств (11 типов)</li>"
            "<li>OUI-база производителей MAC</li>"
            "<li>Интерактивный граф с фигурами по типу</li>"
            "<li>Мониторинг в реальном времени</li>"
            "<li>История в SQLite, сохранение проектов</li>"
            "<li>Экспорт PNG/CSV</li>"
            "</ul>"
            "<p style='color:#c62828'><b>Только для собственных сетей!</b></p>")

    def closeEvent(self, event):
        for t in (self.worker, self.monitor):
            if t and t.isRunning():
                t.stop(); t.wait(2000)
        event.accept()


# ==================== ENTRY ====================

# FIX #5: проверка админа ДО QApplication, но с ручным созданием app для диалога
def main():
    if IS_WIN and not is_admin():
        # создаём минимальный QApplication только чтобы показать диалог
        tmp = QApplication.instance() or QApplication(sys.argv)
        r = QMessageBox.question(
            None, "Права администратора",
            "Для полного сканирования (ARP, ICMP без потерь) нужны права "
            "администратора.\n\nПерезапустить с правами администратора?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if r == QMessageBox.StandardButton.Yes:
            elevate_and_exit()

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("NetScan GUI")
    app.setStyle("Fusion")

    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()