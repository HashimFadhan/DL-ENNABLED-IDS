"""
Alert Manager — creates, deduplicates, correlates and retrieves security alerts.
Every alert is traced with full context so analysts can reconstruct exactly
what triggered it.
"""

import json
import logging
import time
from datetime import datetime, timedelta

from models.database import db, Alert

logger = logging.getLogger(__name__)


class AlertManager:

    def __init__(self, app):
        self.app     = app
        self._recent: list = []   # [(key, timestamp)] dedup cache

    # ── create ───────────────────────────────────────────────────────────

    def create_alert(self, source_ip: str, risk_score: float,
                     risk_level: str, description: str,
                     context: dict = None) -> Alert | None:
        """
        Persist a new alert and return the ORM object.
        Duplicate alerts for the same (ip, description) within 5 min are dropped.
        """
        now = time.time()
        key = f'{source_ip}:{description}'

        # ── deduplication ────────────────────────────────────────────────
        for k, ts in self._recent:
            if k == key and now - ts < 300:
                logger.debug('Duplicate suppressed: %s', key)
                return None

        self._recent.append((key, now))
        if len(self._recent) > 200:
            self._recent.sort(key=lambda x: x[1], reverse=True)
            self._recent = self._recent[:100]

        # ── build trace context ──────────────────────────────────────────
        trace = self._build_trace(source_ip, risk_score, risk_level,
                                  description, context or {})

        try:
            alert = Alert(
                source_ip   = source_ip,
                risk_score  = round(risk_score, 2),
                risk_level  = risk_level,
                description = description,
                context     = json.dumps(trace),
                resolved    = False,
            )
            db.session.add(alert)
            db.session.commit()

            logger.info(
                '[ALERT][%s] id=%d  src=%s  score=%.1f  reason="%s"',
                risk_level, alert.id, source_ip, risk_score, description
            )

            self._correlate(alert)
            return alert

        except Exception as exc:
            logger.error('create_alert failed: %s', exc)
            db.session.rollback()
            return None

    # ── resolve ──────────────────────────────────────────────────────────

    def resolve_alert(self, alert_id: int, notes: str = None) -> bool:
        try:
            alert = db.session.get(Alert, alert_id)
            if not alert:
                logger.warning('Alert %d not found', alert_id)
                return False
            alert.resolved        = True
            alert.resolution_time = datetime.now()
            if notes:
                alert.notes = notes
            db.session.commit()
            logger.info('Alert %d resolved', alert_id)
            return True
        except Exception as exc:
            logger.error('resolve_alert: %s', exc)
            db.session.rollback()
            return False

    # ── query ────────────────────────────────────────────────────────────

    def get_alerts(self, limit=50, offset=0,
                   risk_level=None, resolved=None, source_ip=None) -> list:
        try:
            q = Alert.query
            if risk_level:
                q = q.filter(Alert.risk_level == risk_level)
            if resolved is not None:
                q = q.filter(Alert.resolved == resolved)
            if source_ip:
                q = q.filter(Alert.source_ip == source_ip)
            return q.order_by(Alert.timestamp.desc()).limit(limit).offset(offset).all()
        except Exception as exc:
            logger.error('get_alerts: %s', exc)
            return []

    def get_statistics(self) -> dict:
        try:
            total      = Alert.query.count()
            unresolved = Alert.query.filter_by(resolved=False).count()
            high       = Alert.query.filter_by(risk_level='High').count()
            medium     = Alert.query.filter_by(risk_level='Medium').count()
            low        = Alert.query.filter_by(risk_level='Low').count()

            top_q = (db.session.query(Alert.source_ip,
                                      db.func.count(Alert.id).label('cnt'))
                     .group_by(Alert.source_ip)
                     .order_by(db.desc('cnt')).limit(10))

            trend_q = (db.session.query(
                           db.func.date(Alert.timestamp).label('d'),
                           db.func.count(Alert.id).label('cnt'))
                       .group_by('d').order_by(db.desc('d')).limit(7))

            return {
                'total':      total,
                'unresolved': unresolved,
                'by_severity': {'high': high, 'medium': medium, 'low': low},
                'top_sources': [(ip, cnt) for ip, cnt in top_q],
                'trend':       [(str(d), cnt) for d, cnt in trend_q],
            }
        except Exception as exc:
            logger.error('get_statistics: %s', exc)
            return {'total': 0, 'unresolved': 0,
                    'by_severity': {'high':0,'medium':0,'low':0},
                    'top_sources': [], 'trend': []}

    # ── internal ─────────────────────────────────────────────────────────

    @staticmethod
    def _build_trace(source_ip, risk_score, risk_level,
                     description, context: dict) -> dict:
        """
        Augment the raw context dict with a structured trace block so that
        every stored alert is fully self-describing.
        """
        return {
            # ── identity ────────────────────────────────────────────────
            'trace': {
                'captured_at':  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'source_ip':    source_ip,
                'risk_score':   round(risk_score, 2),
                'risk_level':   risk_level,
                'trigger':      description,
            },
            # ── network flow ────────────────────────────────────────────
            'flow': {
                'src_ip':   context.get('src_ip',   source_ip),
                'src_port': context.get('src_port', 0),
                'dst_ip':   context.get('dst_ip',   ''),
                'dst_port': context.get('dst_port', 0),
                'protocol': context.get('protocol', 0),
                'duration_us': context.get('duration', 0),
                'bytes':    context.get('bytes',   0),
                'packets':  context.get('packets', 0),
            },
            # ── geo / ASN (stub) ─────────────────────────────────────────
            'asn':  context.get('asn', {}),
            # ── raw feature snapshot (whatever extra keys arrived) ───────
            'raw':  {k: v for k, v in context.items()
                     if k not in ('src_ip','src_port','dst_ip','dst_port',
                                  'protocol','duration','bytes','packets','asn')},
        }

    def _correlate(self, new_alert: Alert) -> None:
        """Append related-alert notes from the last 24 h."""
        try:
            cutoff  = datetime.now() - timedelta(hours=24)
            related = (Alert.query
                       .filter(Alert.source_ip == new_alert.source_ip,
                               Alert.id        != new_alert.id,
                               Alert.timestamp  > cutoff)
                       .order_by(Alert.timestamp.desc()).limit(5).all())
            if not related:
                return
            note = 'Correlated alerts (same source, last 24 h):\n' + '\n'.join(
                f'  [{a.id}] {a.timestamp.strftime("%H:%M:%S")} '
                f'{a.risk_level} – {a.description}'
                for a in related
            )
            new_alert.notes = (
                (new_alert.notes + '\n\n' + note) if new_alert.notes else note
            )
            db.session.commit()
        except Exception as exc:
            logger.error('_correlate: %s', exc)
