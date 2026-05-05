import logging
import time

import pandas as pd

from utils.cic_features import CICFeatureExtractor
from utils.feature_helpers import calculate_entropy, extract_tcp_flags

logger = logging.getLogger(__name__)


class PacketPreprocessor:

    def __init__(self):
        self.known_ips          = set()
        self.ip_first_seen      = {}
        self.connection_tracker = {}
        self.cic_extractor      = CICFeatureExtractor()

    # ── public ───────────────────────────────────────────────────────────

    def parse_raw_packet(self, data: bytes) -> dict | None:
        """Parse raw IPv4 bytes → dict. Returns None on failure."""
        try:
            if len(data) < 20:
                return None
            ver = data[0] >> 4
            if ver != 4:
                return None
            ihl  = (data[0] & 0x0F) * 4
            if ihl < 20 or len(data) < ihl:
                return None
            proto = data[9]
            src   = '.'.join(str(b) for b in data[12:16])
            dst   = '.'.join(str(b) for b in data[16:20])
            size  = (data[2] << 8) + data[3]
            pkt   = {'timestamp': time.time(), 'src_ip': src, 'dst_ip': dst,
                     'proto': proto, 'size': size, 'src_port': 0,
                     'dst_port': 0, 'flags': 0}
            if proto == 6 and len(data) >= ihl + 14:
                t = data[ihl:]
                pkt['src_port'] = (t[0] << 8) + t[1]
                pkt['dst_port'] = (t[2] << 8) + t[3]
                pkt['flags']    = t[13] if len(t) > 13 else 0
            elif proto == 17 and len(data) >= ihl + 8:
                u = data[ihl:]
                pkt['src_port'] = (u[0] << 8) + u[1]
                pkt['dst_port'] = (u[2] << 8) + u[3]
            self.cic_extractor.add_packet(pkt)
            return pkt
        except Exception as exc:
            logger.debug('parse_raw_packet: %s', exc)
            return None

    def extract_features(self, df: pd.DataFrame) -> dict:
        if df.empty:
            return {}
        cic = self.cic_extractor.extract_features(completed_only=False)
        if not cic.empty:
            out = {}
            for _, row in cic.iterrows():
                ip = row.get('Src IP')
                if ip:
                    out[ip] = row.to_dict()
            return out
        return self._basic(df)

    # ── internal ─────────────────────────────────────────────────────────

    def _basic(self, df: pd.DataFrame) -> dict:
        now = time.time()
        if 'src_ip' not in df.columns:
            return {}
        for ip in set(df['src_ip'].dropna()) - self.known_ips:
            self.known_ips.add(ip)
            self.ip_first_seen[ip] = now

        out = {}
        for ip, grp in df.groupby('src_ip'):
            if 'size' not in grp.columns:
                continue
            dur = max(0.1, (grp['timestamp'].max() - grp['timestamp'].min())
                      if 'timestamp' in grp.columns else 0.1)
            age = now - self.ip_first_seen.get(ip, now)
            f = {
                'Src IP':                     ip,
                'Total Fwd Packets':          len(grp),
                'Fwd Packet Length Mean':     grp['size'].mean(),
                'Total Length of Fwd Packets':grp['size'].sum(),
                'Fwd Packet Length Std':      grp['size'].std(ddof=0),
                'Flow Packets/s':             len(grp) / dur,
                'ip_age':                     age,
            }
            if 'proto' in grp.columns:
                f['Protocol'] = int(grp['proto'].mode().iloc[0])
            if 'dst_port' in grp.columns:
                f['unique_dst_ports'] = int(grp['dst_port'].nunique())
                f['dst_port_entropy'] = calculate_entropy(grp['dst_port'])
                f['Dst Port'] = int(grp['dst_port'].iloc[0])
            if 'src_port' in grp.columns:
                f['Src Port'] = int(grp['src_port'].iloc[0])
            if 'dst_ip' in grp.columns:
                f['unique_dst_ips'] = int(grp['dst_ip'].nunique())
                f['dst_ip_entropy']  = calculate_entropy(grp['dst_ip'])
                f['Dst IP'] = grp['dst_ip'].iloc[0]
            if 'flags' in grp.columns and 'proto' in grp.columns:
                tcp = grp[grp['proto'] == 6]
                if not tcp.empty:
                    flag_sets = tcp['flags'].apply(extract_tcp_flags)
                    f['SYN Flag Count'] = sum(1 for s in flag_sets if 'S' in s and 'A' not in s)
                    f['RST Flag Count'] = sum(1 for s in flag_sets if 'R' in s)
            self._track_connections(ip, grp)
            if ip in self.connection_tracker:
                ct = self.connection_tracker[ip]
                f['active_connections'] = len(ct['active'])
                f['failed_connections'] = ct['failed']
                f['connection_rate']    = ct['total'] / age if age > 0 else 0.0
            out[ip] = f
        return out

    def _track_connections(self, ip: str, grp: pd.DataFrame) -> None:
        if ip not in self.connection_tracker:
            self.connection_tracker[ip] = {'active': set(), 'failed': 0, 'total': 0}
        needed = {'proto', 'dst_ip', 'dst_port', 'flags'}
        if not needed.issubset(grp.columns):
            return
        ct = self.connection_tracker[ip]
        for _, pkt in grp[grp['proto'] == 6].iterrows():
            dst   = (pkt['dst_ip'], pkt['dst_port'])
            flags = extract_tcp_flags(pkt['flags'])
            if 'S' in flags and 'A' not in flags and dst not in ct['active']:
                ct['active'].add(dst); ct['total'] += 1
            if ('R' in flags or 'F' in flags):
                ct['active'].discard(dst)
                if 'R' in flags:
                    ct['failed'] += 1
