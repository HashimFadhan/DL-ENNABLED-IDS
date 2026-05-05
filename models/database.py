from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()


class Alert(db.Model):
    __tablename__ = 'alert'

    id              = db.Column(db.Integer,  primary_key=True)
    timestamp       = db.Column(db.DateTime, default=datetime.now, index=True)
    source_ip       = db.Column(db.String(50),  index=True)
    risk_score      = db.Column(db.Float)
    risk_level      = db.Column(db.String(20))   # Low / Medium / High
    description     = db.Column(db.String(500))
    context         = db.Column(db.Text)          # JSON blob
    resolved        = db.Column(db.Boolean, default=False, index=True)
    resolution_time = db.Column(db.DateTime, nullable=True)
    notes           = db.Column(db.Text,     nullable=True)

    def to_dict(self):
        result = {
            'id':          self.id,
            'timestamp':   self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip':   self.source_ip,
            'risk_score':  self.risk_score,
            'risk_level':  self.risk_level,
            'description': self.description,
            'resolved':    self.resolved,
            'notes':       self.notes,
        }
        if self.resolution_time:
            result['resolution_time'] = self.resolution_time.strftime('%Y-%m-%d %H:%M:%S')
        if self.context:
            try:
                result['context'] = json.loads(self.context)
            except Exception:
                result['context'] = {}
        return result


class TrafficStats(db.Model):
    __tablename__ = 'traffic_stats'

    id                 = db.Column(db.Integer, primary_key=True)
    timestamp          = db.Column(db.DateTime, default=datetime.now, index=True)
    packets            = db.Column(db.Integer)
    packets_per_second = db.Column(db.Float)
    bytes_total        = db.Column(db.Integer,  nullable=True)
    bytes_per_second   = db.Column(db.Float,    nullable=True)
    active_flows       = db.Column(db.Integer,  nullable=True)
    _top_ips           = db.Column('top_ips',        db.Text)
    _protocol_stats    = db.Column('protocol_stats', db.Text)

    @property
    def top_ips(self):
        return json.loads(self._top_ips) if self._top_ips else {}

    @top_ips.setter
    def top_ips(self, value):
        self._top_ips = json.dumps(value) if isinstance(value, dict) else None

    @property
    def protocol_stats(self):
        return json.loads(self._protocol_stats) if self._protocol_stats else {}

    @protocol_stats.setter
    def protocol_stats(self, value):
        self._protocol_stats = json.dumps(value) if isinstance(value, dict) else None

    def to_dict(self):
        return {
            'id':                 self.id,
            'timestamp':          self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'packets':            self.packets,
            'packets_per_second': self.packets_per_second,
            'bytes_total':        self.bytes_total,
            'bytes_per_second':   self.bytes_per_second,
            'active_flows':       self.active_flows,
            'top_ips':            self.top_ips,
            'protocol_stats':     self.protocol_stats,
        }

    @classmethod
    def get_historical_stats(cls, hours=24):
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(hours=hours)
        return cls.query.filter(cls.timestamp > cutoff).order_by(cls.timestamp).all()


class SystemConfig(db.Model):
    __tablename__ = 'system_config'

    id                          = db.Column(db.Integer, primary_key=True)
    capture_interface           = db.Column(db.String(50))
    ml_detection_enabled        = db.Column(db.Boolean, default=True)
    signature_detection_enabled = db.Column(db.Boolean, default=True)
    anomaly_detection_enabled   = db.Column(db.Boolean, default=True)
    alert_threshold             = db.Column(db.Integer, default=3)
    packet_buffer_size          = db.Column(db.Integer, default=1000)
    log_level                   = db.Column(db.String(10), default='INFO')
    last_updated                = db.Column(db.DateTime, default=datetime.now,
                                            onupdate=datetime.now)
