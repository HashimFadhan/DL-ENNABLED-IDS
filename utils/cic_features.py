"""
Bidirectional flow tracker that computes CIC-IDS 2018 compatible features
from a stream of parsed packet dictionaries.
"""
import time
import logging
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)
FLOW_TIMEOUT = 120   # seconds


class FlowRecord:
    __slots__ = [
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto',
        'start_ts', 'last_ts',
        'fwd_lens', 'bwd_lens',
        'fwd_ts', 'bwd_ts',
        'fwd_flags', 'bwd_flags',
        'fwd_init_win', 'bwd_init_win',
    ]

    def __init__(self, src_ip, src_port, dst_ip, dst_port, proto, ts):
        self.src_ip, self.src_port = src_ip, src_port
        self.dst_ip, self.dst_port = dst_ip, dst_port
        self.proto = proto
        self.start_ts = self.last_ts = ts
        self.fwd_lens  = []
        self.bwd_lens  = []
        self.fwd_ts    = []
        self.bwd_ts    = []
        self.fwd_flags = []
        self.bwd_flags = []
        self.fwd_init_win = -1
        self.bwd_init_win = -1


class CICFeatureExtractor:

    def __init__(self):
        self._flows: dict = {}
        self._done:  list = []

    def add_packet(self, pkt: dict) -> None:
        try:
            ts       = float(pkt.get('timestamp', time.time()))
            src_ip   = str(pkt.get('src_ip', ''))
            dst_ip   = str(pkt.get('dst_ip', ''))
            src_port = int(pkt.get('src_port', 0))
            dst_port = int(pkt.get('dst_port', 0))
            proto    = int(pkt.get('proto', 0))
            size     = int(pkt.get('size', 0))
            flags    = int(pkt.get('flags', 0))

            fwd_key = (src_ip, src_port, dst_ip, dst_port, proto)
            bwd_key = (dst_ip, dst_port, src_ip, src_port, proto)

            if fwd_key in self._flows:
                f = self._flows[fwd_key]
                f.fwd_lens.append(size); f.fwd_ts.append(ts)
                f.fwd_flags.append(flags); f.last_ts = ts
            elif bwd_key in self._flows:
                f = self._flows[bwd_key]
                f.bwd_lens.append(size); f.bwd_ts.append(ts)
                f.bwd_flags.append(flags); f.last_ts = ts
            else:
                f = FlowRecord(src_ip, src_port, dst_ip, dst_port, proto, ts)
                f.fwd_lens.append(size); f.fwd_ts.append(ts)
                f.fwd_flags.append(flags)
                self._flows[fwd_key] = f

            # FIN or RST ends the flow
            if proto == 6 and (flags & 0x01 or flags & 0x04):
                key = fwd_key if fwd_key in self._flows else bwd_key
                self._finish(key)
        except Exception as exc:
            logger.debug('CICFeatureExtractor.add_packet: %s', exc)

    def extract_features(self, completed_only=True) -> pd.DataFrame:
        self._expire()
        records = list(self._done)
        self._done.clear()
        if not completed_only:
            records += list(self._flows.values())
        if not records:
            return pd.DataFrame()
        return pd.DataFrame([self._to_row(r) for r in records])

    # ── internal ─────────────────────────────────────────────────────────

    def _finish(self, key):
        f = self._flows.pop(key, None)
        if f:
            self._done.append(f)

    def _expire(self):
        now = time.time()
        for k in [k for k, f in self._flows.items()
                  if now - f.last_ts > FLOW_TIMEOUT]:
            self._finish(k)

    @staticmethod
    def _stats(lst):
        if not lst:
            return 0.0, 0.0, 0.0, 0.0
        a = np.asarray(lst, dtype=float)
        return float(a.mean()), float(a.std()), float(a.max()), float(a.min())

    @staticmethod
    def _iat(ts_list):
        s = sorted(ts_list)
        return [s[i+1]-s[i] for i in range(len(s)-1)] if len(s) > 1 else []

    @staticmethod
    def _flag_cnt(lst, bit):
        return sum(1 for f in lst if f & (1 << bit))

    def _to_row(self, f: FlowRecord) -> dict:
        dur = max(0.0, (f.last_ts - f.start_ts) * 1_000_000)
        fm, fs, fmx, fmn = self._stats(f.fwd_lens)
        bm, bs, bmx, bmn = self._stats(f.bwd_lens)
        all_lens  = f.fwd_lens + f.bwd_lens
        pm, ps, pmx, pmn = self._stats(all_lens)
        all_ts    = sorted(f.fwd_ts + f.bwd_ts)
        fi  = self._iat(all_ts)
        ffi = self._iat(f.fwd_ts)
        bfi = self._iat(f.bwd_ts)
        fism, fiss, fismx, fismn = self._stats(fi)
        ffm, ffs, ffmx, ffmn     = self._stats(ffi)
        bfm, bfs, bfmx, bfmn     = self._stats(bfi)
        af = f.fwd_flags + f.bwd_flags
        tot_b = sum(all_lens)
        tot_f = len(f.fwd_lens)
        tot_bk = len(f.bwd_lens)
        bps = tot_b / (dur/1e6) if dur > 0 else 0.0
        pps = (tot_f + tot_bk) / (dur/1e6) if dur > 0 else 0.0
        return {
            'Src IP': f.src_ip, 'Src Port': f.src_port,
            'Dst IP': f.dst_ip, 'Dst Port': f.dst_port,
            'Protocol': f.proto, 'Flow Duration': dur,
            'Tot Fwd Pkts': tot_f, 'Tot Bwd Pkts': tot_bk,
            'TotLen Fwd Pkts': sum(f.fwd_lens), 'TotLen Bwd Pkts': sum(f.bwd_lens),
            'Fwd Pkt Len Max': fmx, 'Fwd Pkt Len Min': fmn,
            'Fwd Pkt Len Mean': fm, 'Fwd Pkt Len Std': fs,
            'Bwd Pkt Len Max': bmx, 'Bwd Pkt Len Min': bmn,
            'Bwd Pkt Len Mean': bm, 'Bwd Pkt Len Std': bs,
            'Flow Byts/s': bps, 'Flow Pkts/s': pps,
            'Flow IAT Mean': fism, 'Flow IAT Std': fiss,
            'Flow IAT Max': fismx, 'Flow IAT Min': fismn,
            'Fwd IAT Tot': sum(ffi), 'Fwd IAT Mean': ffm,
            'Fwd IAT Std': ffs, 'Fwd IAT Max': ffmx, 'Fwd IAT Min': ffmn,
            'Bwd IAT Tot': sum(bfi), 'Bwd IAT Mean': bfm,
            'Bwd IAT Std': bfs, 'Bwd IAT Max': bfmx, 'Bwd IAT Min': bfmn,
            'Fwd PSH Flags': self._flag_cnt(f.fwd_flags, 3),
            'Bwd PSH Flags': self._flag_cnt(f.bwd_flags, 3),
            'Fwd URG Flags': self._flag_cnt(f.fwd_flags, 5),
            'Bwd URG Flags': self._flag_cnt(f.bwd_flags, 5),
            'FIN Flag Cnt': self._flag_cnt(af, 0),
            'SYN Flag Cnt': self._flag_cnt(af, 1),
            'RST Flag Cnt': self._flag_cnt(af, 2),
            'PSH Flag Cnt': self._flag_cnt(af, 3),
            'ACK Flag Cnt': self._flag_cnt(af, 4),
            'URG Flag Cnt': self._flag_cnt(af, 5),
            'Pkt Len Min': pmn, 'Pkt Len Max': pmx,
            'Pkt Len Mean': pm, 'Pkt Len Std': ps, 'Pkt Len Var': ps**2,
            'Pkt Size Avg': pm,
            'Down/Up Ratio': tot_bk/tot_f if tot_f > 0 else 0.0,
            'Init Fwd Win Byts': f.fwd_init_win,
            'Init Bwd Win Byts': f.bwd_init_win,
            'Fwd Act Data Pkts': sum(1 for l in f.fwd_lens if l > 0),
        }
