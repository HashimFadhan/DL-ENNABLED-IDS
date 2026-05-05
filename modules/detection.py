"""
Hybrid Detection Engine
  ① Signature-based  (JSON rule files)
  ② ML ensemble      (Random Forest + Gradient Boosting + MLP)
  ③ Statistical anomaly heuristics
  ④ IP reputation     (session-level repeat-offender tracking)

Every detection decision is logged at DEBUG level with its reason so the
full alert trace can be reconstructed from the log file.
"""

import json
import logging
import os
import time

import joblib
import numpy as np

from utils.network_utils import is_private_ip, lookup_asn

logger = logging.getLogger(__name__)


class DetectionEngine:

    def __init__(self, app, alert_manager,
                 ml_enabled=True, signature_enabled=True,
                 anomaly_enabled=True, alert_threshold=3):
        self.app               = app
        self.alert_manager     = alert_manager
        self.ml_enabled        = ml_enabled
        self.signature_enabled = signature_enabled
        self.anomaly_enabled   = anomaly_enabled
        self.alert_threshold   = alert_threshold

        self.models:        dict = {}
        self.signatures:    list = []
        self.scaler              = None
        self.feature_names: list = []

        self.ip_reputation:  dict = {}
        self.whitelisted_ips: set = {'127.0.0.1', '::1'}
        self.asn_cache:      dict = {}

        self._load_resources()
        self._load_whitelist()

        logger.info(
            'DetectionEngine ready  ML:%s  Sig:%s  Anomaly:%s  threshold:%d',
            '✓' if ml_enabled else '✗',
            '✓' if signature_enabled else '✗',
            '✓' if anomaly_enabled else '✗',
            alert_threshold,
        )

    # ══════════════════════════════════════════════════════════════════════
    # Main entry point
    # ══════════════════════════════════════════════════════════════════════

    def analyze_traffic(self, flow_features: dict) -> None:
        if not flow_features:
            return

        for _fid, features in flow_features.items():
            src_ip = features.get('Src IP', features.get('src_ip', ''))
            if not src_ip:
                continue
            if src_ip in self.whitelisted_ips or is_private_ip(src_ip):
                continue
            if len(features) < 5:
                continue

            score   = 0.0
            reasons = []

            # ── 1. Signatures ────────────────────────────────────────────
            if self.signature_enabled and self.signatures:
                s, r = self._signatures(features)
                score += s; reasons += r

            # ── 2. ML ────────────────────────────────────────────────────
            if self.ml_enabled and self.models and self.scaler and self.feature_names:
                s, r = self._ml(features)
                score += s; reasons += r

            # ── 3. Anomaly ───────────────────────────────────────────────
            if self.anomaly_enabled:
                s, r = self._anomaly(features)
                score += s; reasons += r

            # ── 4. Reputation ────────────────────────────────────────────
            s, r = self._reputation(src_ip)
            if s > 0:
                score += s; reasons.append(r)

            score = min(10.0, score)

            logger.debug(
                '[DETECTION] src=%s  score=%.2f  reasons=%s',
                src_ip, score, reasons
            )

            if score >= self.alert_threshold and reasons:
                level = ('High' if score >= 7 else
                         'Medium' if score >= 5 else 'Low')

                if src_ip not in self.asn_cache:
                    self.asn_cache[src_ip] = lookup_asn(src_ip)

                context = {
                    'src_ip':   src_ip,
                    'src_port': features.get('Src Port',  features.get('src_port', 0)),
                    'dst_ip':   features.get('Dst IP',    features.get('dst_ip', '')),
                    'dst_port': features.get('Dst Port',  features.get('dst_port', 0)),
                    'protocol': features.get('Protocol',  features.get('proto', 0)),
                    'duration': features.get('Flow Duration', 0),
                    'bytes':    (features.get('TotLen Fwd Pkts', 0)
                                 + features.get('TotLen Bwd Pkts', 0)),
                    'packets':  (features.get('Tot Fwd Pkts', 0)
                                 + features.get('Tot Bwd Pkts', 0)),
                    'asn':      self.asn_cache[src_ip],
                    # attach the raw feature snapshot for full traceability
                    'features_snapshot': {
                        k: (float(v) if isinstance(v, (int, float, np.integer,
                                                        np.floating)) else str(v))
                        for k, v in features.items()
                        if k not in ('Src IP', 'Dst IP')
                    },
                }

                with self.app.app_context():
                    self.alert_manager.create_alert(
                        source_ip   = src_ip,
                        risk_score  = score,
                        risk_level  = level,
                        description = ' | '.join(reasons),
                        context     = context,
                    )

                self._update_reputation(src_ip)

    # ══════════════════════════════════════════════════════════════════════
    # Detection methods
    # ══════════════════════════════════════════════════════════════════════

    def _signatures(self, features: dict):
        matches, total = [], 0.0
        for sig in self.signatures:
            rules = sig.get('rules', [])
            if not rules:
                continue
            hits, wsum = 0, 0.0
            for rule in rules:
                feat = rule.get('feature')
                if feat not in features:
                    continue
                val = features[feat]
                op  = rule.get('operator')
                thr = rule.get('threshold')
                w   = rule.get('weight', 1.0)
                try:
                    hit = (op == '>'  and float(val) > float(thr)  or
                           op == '<'  and float(val) < float(thr)  or
                           op == '>=' and float(val) >= float(thr) or
                           op == '<=' and float(val) <= float(thr) or
                           op == '==' and float(val) == float(thr))
                except (TypeError, ValueError):
                    hit = False
                if hit:
                    hits += 1; wsum += w
            pct = hits / len(rules)
            if pct >= 0.7:
                avg_w = wsum / hits if hits else 0.0
                total += min(5.0, 3.0 + avg_w / 2.0)
                matches.append(f"{sig.get('name','Sig')} ({pct:.0%})")

        if matches:
            return min(7.0, total), [f'Signature match: {", ".join(matches)}']
        return 0.0, []

    def _ml(self, features: dict):
        try:
            vec     = [float(features.get(n, 0.0)) for n in self.feature_names]
            X_sc    = self.scaler.transform(np.array([vec]))
            positives = []
            for name, model in self.models.items():
                if model.predict(X_sc)[0] == 1:
                    if hasattr(model, 'predict_proba'):
                        conf = float(model.predict_proba(X_sc)[0][1])
                    elif hasattr(model, 'decision_function'):
                        dv   = model.decision_function(X_sc)[0]
                        conf = float(1 / (1 + np.exp(-dv)))
                    else:
                        conf = 0.8
                    positives.append((name, conf))

            if positives:
                agreement = len(positives) / max(1, len(self.models))
                avg_conf  = sum(c for _, c in positives) / len(positives)
                score     = min(8.0, 3.0 + agreement * 3.0 + avg_conf * 2.0)
                names     = ', '.join(n for n, _ in positives)
                return score, [
                    f'ML: {len(positives)}/{len(self.models)} models ({names}, '
                    f'conf {avg_conf:.2f})'
                ]
            return 0.0, []
        except Exception as exc:
            logger.debug('_ml: %s', exc)
            return 0.0, []

    def _anomaly(self, features: dict):
        hits, score = [], 0.0

        # Port scan
        if features.get('dst_port_entropy', 0) > 4.0:
            hits.append('high port entropy'); score += 2.5
        if features.get('unique_dst_ports', 0) > 10:
            hits.append(f"port scan ({int(features['unique_dst_ports'])} ports)")
            score += 2.0

        # High packet rate
        dur = features.get('Flow Duration', 0)
        fwd = features.get('Tot Fwd Pkts', features.get('Total Fwd Packets', 0))
        if dur and dur > 0 and fwd:
            pps = fwd / (dur / 1_000_000)
            if pps > 100:
                hits.append(f'high PPS ({pps:.0f})'); score += 2.0

        # Brute-force pattern
        syn = features.get('SYN Flag Cnt', features.get('SYN Flag Count', 0))
        rst = features.get('RST Flag Cnt', features.get('RST Flag Count', 0))
        if syn > 5 and rst > 3 and 0.5 <= syn / max(rst, 1) <= 2.0:
            hits.append('brute-force SYN/RST ratio'); score += 2.5

        # Data exfiltration
        dst_ip  = features.get('Dst IP', features.get('dst_ip', ''))
        flow_bps = features.get('Flow Byts/s', 0)
        if dst_ip and not is_private_ip(dst_ip) and flow_bps > 100_000:
            hits.append(f'exfiltration {flow_bps/1000:.0f} KB/s'); score += 2.0

        # Unusual packet size
        fwd_m = features.get('Fwd Pkt Len Mean', features.get('Fwd Packet Length Mean', 0))
        if fwd_m and (fwd_m < 40 or fwd_m > 1400):
            hits.append(f'unusual pkt size {fwd_m:.0f} B'); score += 1.5

        # DDoS reflection
        bwd = features.get('Tot Bwd Pkts', 0)
        if fwd < 5 and bwd > 20:
            hits.append('DDoS reflection'); score += 3.0

        score = min(7.0, score)
        if hits:
            return score, [f'Anomaly: {", ".join(hits)}']
        return 0.0, []

    def _reputation(self, ip: str):
        if ip not in self.ip_reputation:
            return 0.0, ''
        cnt, last = self.ip_reputation[ip]
        age = time.time() - last
        if age < 3600:
            if cnt >= 5: return 3.0, f'Repeat offender ({cnt} alerts, <1 h)'
            if cnt >= 3: return 2.0, f'Repeat offender ({cnt} alerts)'
            return 1.0, f'Previously flagged ({cnt} alerts)'
        if age < 86400:
            return (2.0 if cnt >= 5 else 1.0), f'Known bad actor ({cnt} alerts)'
        return 0.0, ''

    def _update_reputation(self, ip: str) -> None:
        now = time.time()
        cnt, _ = self.ip_reputation.get(ip, (0, now))
        self.ip_reputation[ip] = (cnt + 1, now)
        cutoff = now - 7 * 86400
        self.ip_reputation = {
            k: v for k, v in self.ip_reputation.items() if v[1] > cutoff
        }

    # ══════════════════════════════════════════════════════════════════════
    # Resource loading
    # ══════════════════════════════════════════════════════════════════════

    def _load_resources(self) -> None:
        from config import BASE_DIR
        model_dir = os.path.join(BASE_DIR, 'data', 'ml_models')
        sig_dir   = os.path.join(BASE_DIR, 'data', 'signatures')

        if os.path.isdir(model_dir):
            sp = os.path.join(model_dir, 'feature_scaler.pkl')
            if os.path.exists(sp):
                try:
                    self.scaler = joblib.load(sp)
                    logger.info('Scaler loaded')
                except Exception as exc:
                    logger.warning('Scaler load failed: %s', exc)

            fp = os.path.join(model_dir, 'feature_names.txt')
            if os.path.exists(fp):
                try:
                    self.feature_names = [l.strip() for l in open(fp) if l.strip()]
                    logger.info('%d feature names loaded', len(self.feature_names))
                except Exception as exc:
                    logger.warning('Feature names load failed: %s', exc)

            for fn in os.listdir(model_dir):
                if fn.endswith('_model.pkl'):
                    name = fn[:-len('_model.pkl')]
                    try:
                        self.models[name] = joblib.load(os.path.join(model_dir, fn))
                        logger.info('Model loaded: %s', name)
                    except Exception as exc:
                        logger.warning('Model %s failed: %s', name, exc)

        if os.path.isdir(sig_dir):
            for fn in os.listdir(sig_dir):
                if fn.endswith('.json'):
                    try:
                        with open(os.path.join(sig_dir, fn)) as fh:
                            self.signatures.append(json.load(fh))
                    except Exception as exc:
                        logger.warning('Sig %s failed: %s', fn, exc)
            logger.info('%d signature(s) loaded', len(self.signatures))

    def _load_whitelist(self) -> None:
        from config import BASE_DIR
        wl = os.path.join(BASE_DIR, 'data', 'config', 'whitelist.json')
        if os.path.exists(wl):
            try:
                data = json.load(open(wl))
                self.whitelisted_ips.update(data.get('ips', []))
                logger.info('%d whitelisted IPs', len(self.whitelisted_ips))
            except Exception as exc:
                logger.warning('Whitelist load failed: %s', exc)
