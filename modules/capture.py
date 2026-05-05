"""
Packet Capture Manager
Supports: Scapy (Windows/Linux/Mac), Linux AF_PACKET, Windows raw sockets.
"""

import logging
import socket
import threading
import time

import pandas as pd

from modules.preprocessing import PacketPreprocessor
from models.database import TrafficStats, db
from utils.network_utils import is_admin

logger = logging.getLogger(__name__)


class PacketCaptureManager:

    def __init__(self, app, detection_engine, interface=None, buffer_size=1000):
        self.app              = app
        self.detection_engine = detection_engine
        self.interface        = interface
        self.buffer_size      = buffer_size
        self.running          = False
        self.preprocessor     = PacketPreprocessor()

        self.stats = {
            'total_packets': 0,
            'pps':           0.0,
            'top_ips':       {},
            'protocol_stats':{},
            'port_stats':    {},
            'start_time':    time.time(),
            'last_updated':  time.time(),
        }
        self._buf  = []
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None

    # ── lifecycle ─────────────────────────────────────────────────────────

    def start_capture(self) -> None:
        self.running = True
        if is_admin():
            if hasattr(socket, 'AF_PACKET'):
                self._linux_capture()
            else:
                self._windows_capture()
        else:
            logger.warning(
                'No admin privileges — using Scapy. '
                'Windows: install Npcap and run as Administrator.'
            )
            self._scapy_capture()
        self._start_stats_recorder()

    def stop_capture(self) -> None:
        self.running = False
        if self._timer:
            self._timer.cancel()
        logger.info('Capture stopped')

    def is_running(self) -> bool:
        return self.running

    def get_traffic_stats(self) -> dict:
        if time.time() - self.stats['last_updated'] > 5:
            self.stats['pps'] = 0.0
        return self.stats

    def get_total_packets(self) -> int:
        return self.stats['total_packets']

    # ── packet ingestion ──────────────────────────────────────────────────

    def _ingest(self, pkt_dict: dict) -> None:
        with self._lock:
            self._buf.append(pkt_dict)
            self.stats['total_packets'] += 1
            now = time.time()
            elapsed = now - self.stats['last_updated']
            if elapsed >= 1.0:
                self.stats['pps']          = len(self._buf) / elapsed
                self.stats['last_updated'] = now
            if len(self._buf) >= self.buffer_size:
                self._flush()

    def _flush(self) -> None:
        """Process buffered packets (must be called with _lock held)."""
        if not self._buf:
            return
        df = pd.DataFrame(self._buf)
        self._update_stats(df)
        features = self.preprocessor.extract_features(df)
        self.detection_engine.analyze_traffic(features)
        self._buf.clear()

    def _update_stats(self, df: pd.DataFrame) -> None:
        if 'src_ip' in df.columns:
            self.stats['top_ips'] = df['src_ip'].value_counts().head(10).to_dict()
        if 'proto' in df.columns:
            m = {1:'ICMP', 6:'TCP', 17:'UDP'}
            self.stats['protocol_stats'] = (
                df['proto'].map(lambda p: m.get(p, f'Other({p})'))
                .value_counts().to_dict()
            )
        if 'dst_port' in df.columns:
            self.stats['port_stats'] = df['dst_port'].value_counts().head(5).to_dict()

    # ── stats recorder ────────────────────────────────────────────────────

    def _start_stats_recorder(self) -> None:
        def record():
            try:
                if self.stats['total_packets'] > 0:
                    with self.app.app_context():
                        db.session.add(TrafficStats(
                            packets            = self.stats['total_packets'],
                            packets_per_second = self.stats['pps'],
                            top_ips            = self.stats['top_ips'],
                            protocol_stats     = self.stats['protocol_stats'],
                        ))
                        db.session.commit()
            except Exception as exc:
                logger.error('Stats record error: %s', exc)
            finally:
                if self.running:
                    self._timer = threading.Timer(300, record)
                    self._timer.daemon = True
                    self._timer.start()
        self._timer = threading.Timer(300, record)
        self._timer.daemon = True
        self._timer.start()

    # ── capture backends ──────────────────────────────────────────────────

    def _scapy_capture(self) -> None:
        logger.info('Scapy capture on interface: %s', self.interface)
        try:
            from scapy.all import sniff, IP, TCP, UDP

            def handler(pkt):
                if not self.running or IP not in pkt:
                    return
                d = {
                    'timestamp': time.time(),
                    'src_ip':    pkt[IP].src,
                    'dst_ip':    pkt[IP].dst,
                    'size':      len(pkt),
                    'proto':     pkt[IP].proto,
                    'src_port':  0, 'dst_port': 0, 'flags': 0,
                }
                if TCP in pkt:
                    d.update(src_port=pkt[TCP].sport, dst_port=pkt[TCP].dport,
                             flags=int(pkt[TCP].flags))
                elif UDP in pkt:
                    d.update(src_port=pkt[UDP].sport, dst_port=pkt[UDP].dport)
                self._ingest(d)

            sniff(iface=self.interface, prn=handler, filter='ip', store=False)
        except ImportError:
            logger.error('Scapy not installed. Run: pip install scapy')
            self.running = False
        except Exception as exc:
            logger.error('Scapy error: %s', exc)
            self.running = False

    def _linux_capture(self) -> None:
        logger.info('Linux raw socket on: %s', self.interface)
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.interface:
                s.bind((self.interface, 0))
            s.settimeout(1.0)
            while self.running:
                try:
                    raw = s.recv(65535)
                    d = self.preprocessor.parse_raw_packet(raw[14:])  # strip Ethernet
                    if d:
                        self._ingest(d)
                except socket.timeout:
                    pass
                except Exception as exc:
                    logger.error('Linux capture: %s', exc)
        except Exception as exc:
            logger.error('Linux socket init: %s', exc)
            self.running = False

    def _windows_capture(self) -> None:
        logger.info('Windows raw socket capture')
        try:
            host = socket.gethostbyname(socket.gethostname())
            s    = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((host, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            s.settimeout(1.0)
            while self.running:
                try:
                    raw, _ = s.recvfrom(65535)
                    d = self.preprocessor.parse_raw_packet(raw)
                    if d:
                        self._ingest(d)
                except socket.timeout:
                    pass
                except Exception as exc:
                    logger.error('Windows capture: %s', exc)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception as exc:
            logger.error('Windows socket init: %s', exc)
            self.running = False
