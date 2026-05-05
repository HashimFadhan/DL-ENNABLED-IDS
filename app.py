"""
CIC-IDS 2018 Network Intrusion Detection System
Flask application — all routes, API endpoints, and startup logic.
"""

import json
import logging
import os
import threading
import time

from flask import (Flask, jsonify, redirect, render_template,
                   request, url_for, flash)

# ── absolute base dir (fixes sqlite path on Windows) ───────────────────
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ── create ALL required directories BEFORE anything else ───────────────
for _d in ['data', 'data/logs', 'data/ml_models',
           'data/signatures', 'data/config', 'data/cic_ids2018']:
    os.makedirs(os.path.join(BASE_DIR, _d), exist_ok=True)

# ── default whitelist ───────────────────────────────────────────────────
_WL = os.path.join(BASE_DIR, 'data', 'config', 'whitelist.json')
if not os.path.exists(_WL):
    with open(_WL, 'w') as _f:
        json.dump({'ips': ['127.0.0.1', '::1']}, _f, indent=2)

# ── logging ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s  %(name)-28s  %(levelname)-8s  %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(BASE_DIR, 'data', 'logs', 'ids.log')),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# ── now safe to import project modules ──────────────────────────────────
import config as cfg
from models.database import db, Alert, TrafficStats, SystemConfig
from modules.capture   import PacketCaptureManager
from modules.detection import DetectionEngine
from modules.storage   import AlertManager
from utils.network_utils import get_network_interfaces

# ── Flask app ────────────────────────────────────────────────────────────
app = Flask(__name__,
            static_folder='static',
            template_folder='templates')
app.config.from_object(cfg.Config)
app.secret_key = app.config['SECRET_KEY']
db.init_app(app)

# ── global service handles ────────────────────────────────────────────────
capture_manager:  PacketCaptureManager | None = None
detection_engine: DetectionEngine      | None = None
alert_manager:    AlertManager         | None = None


# ════════════════════════════════════════════════════════════════════════════
# Initialisation
# ════════════════════════════════════════════════════════════════════════════

def init_database() -> None:
    with app.app_context():
        db.create_all()
        if SystemConfig.query.first() is None:
            ifaces = get_network_interfaces()
            iface  = ifaces[0][0] if ifaces else 'eth0'
            db.session.add(SystemConfig(
                capture_interface           = iface,
                ml_detection_enabled        = True,
                signature_detection_enabled = True,
                anomaly_detection_enabled   = True,
                alert_threshold             = 3,
                packet_buffer_size          = 1000,
                log_level                   = 'INFO',
            ))
            db.session.commit()
            logger.info('Default system config created (interface: %s)', iface)
        logger.info('Database ready')


def start_services() -> None:
    global capture_manager, detection_engine, alert_manager

    with app.app_context():
        sys_cfg = SystemConfig.query.first()

    alert_manager    = AlertManager(app)
    detection_engine = DetectionEngine(
        app, alert_manager,
        ml_enabled        = sys_cfg.ml_detection_enabled,
        signature_enabled = sys_cfg.signature_detection_enabled,
        anomaly_enabled   = sys_cfg.anomaly_detection_enabled,
        alert_threshold   = sys_cfg.alert_threshold,
    )
    capture_manager = PacketCaptureManager(
        app, detection_engine,
        interface   = sys_cfg.capture_interface,
        buffer_size = sys_cfg.packet_buffer_size,
    )

    t = threading.Thread(target=capture_manager.start_capture, daemon=True)
    t.start()
    logger.info('Capture thread started on interface: %s', sys_cfg.capture_interface)


# ════════════════════════════════════════════════════════════════════════════
# HTML routes
# ════════════════════════════════════════════════════════════════════════════

@app.route('/')
def dashboard():
    return render_template('dashboard.html')


@app.route('/alerts')
def alerts_page():
    page  = request.args.get('page',  1,     type=int)
    level = request.args.get('level', 'all')
    return render_template('alerts.html', page=page, filter_level=level)


@app.route('/alert/<int:alert_id>')
def alert_detail_page(alert_id):
    with app.app_context():
        alert = db.session.get(Alert, alert_id)
        if alert is None:
            return render_template('404.html'), 404
    return render_template('alert_detail.html', alert=alert)


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        try:
            with app.app_context():
                sc = SystemConfig.query.first()
                sc.capture_interface           = request.form.get('interface', sc.capture_interface)
                sc.ml_detection_enabled        = 'ml_enabled'        in request.form
                sc.signature_detection_enabled = 'signature_enabled' in request.form
                sc.anomaly_detection_enabled   = 'anomaly_enabled'   in request.form
                sc.alert_threshold             = int(request.form.get('threshold', 3))
                sc.packet_buffer_size          = int(request.form.get('buffer_size', 1000))
                sc.log_level                   = request.form.get('log_level', 'INFO')
                db.session.commit()
                flash('Settings saved. Restart required for capture changes.', 'success')
        except Exception as exc:
            flash(f'Error: {exc}', 'danger')
        return redirect(url_for('settings'))

    with app.app_context():
        sc = SystemConfig.query.first()
    return render_template('settings.html',
                           interfaces=get_network_interfaces(), config=sc)


# ════════════════════════════════════════════════════════════════════════════
# API — stats
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/stats/current')
def api_stats_current():
    if not capture_manager:
        return jsonify({'error': 'Capture not running'}), 503
    stats = capture_manager.get_traffic_stats()
    with app.app_context():
        stats['active_alerts'] = Alert.query.filter_by(resolved=False).count()
        stats['total_alerts']  = Alert.query.count()
    return jsonify(stats)


@app.route('/api/stats/history')
def api_stats_history():
    hours = request.args.get('hours', 1, type=int)
    with app.app_context():
        rows = TrafficStats.get_historical_stats(hours)
        return jsonify([r.to_dict() for r in rows])


@app.route('/api/traffic/distribution')
def api_traffic_dist():
    with app.app_context():
        s = TrafficStats.query.order_by(TrafficStats.timestamp.desc()).first()
        if not s:
            return jsonify({'tcp':0,'udp':0,'icmp':0,'other':0})
        p = s.protocol_stats
        return jsonify({
            'tcp':   p.get('TCP',  0),
            'udp':   p.get('UDP',  0),
            'icmp':  p.get('ICMP', 0),
            'other': sum(v for k, v in p.items() if k not in ('TCP','UDP','ICMP')),
        })


@app.route('/api/sources/top')
def api_top_sources():
    with app.app_context():
        s = TrafficStats.query.order_by(TrafficStats.timestamp.desc()).first()
        if not s:
            return jsonify([])
        return jsonify([
            {'ip': ip, 'packets': cnt}
            for ip, cnt in sorted(s.top_ips.items(),
                                  key=lambda x: x[1], reverse=True)[:10]
        ])


# ════════════════════════════════════════════════════════════════════════════
# API — alerts  (full CRUD + trace endpoint)
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/alerts')
def api_alerts():
    limit = request.args.get('limit', 50,   type=int)
    level = request.args.get('level', None)
    resolved = request.args.get('resolved', None)
    source   = request.args.get('source',   None)

    with app.app_context():
        q = Alert.query
        if level and level.lower() != 'all':
            q = q.filter(Alert.risk_level == level.capitalize())
        if resolved is not None:
            q = q.filter(Alert.resolved == (resolved.lower() == 'true'))
        if source:
            q = q.filter(Alert.source_ip == source)
        alerts = q.order_by(Alert.timestamp.desc()).limit(limit).all()
        return jsonify([a.to_dict() for a in alerts])


@app.route('/api/alerts/recent')
def api_alerts_recent():
    """Last 10 alerts in dashboard-table format."""
    with app.app_context():
        rows = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
        return jsonify([{
            'id':          a.id,
            'time':        a.timestamp.strftime('%H:%M:%S'),
            'date':        a.timestamp.strftime('%Y-%m-%d'),
            'source_ip':   a.source_ip,
            'risk_level':  a.risk_level,
            'risk_score':  a.risk_score,
            'description': (a.description or '')[:100],
            'resolved':    a.resolved,
        } for a in rows])


@app.route('/api/alerts/stats')
def api_alert_stats():
    """Aggregate statistics used by the dashboard charts."""
    with app.app_context():
        if not alert_manager:
            return jsonify({})
        return jsonify(alert_manager.get_statistics())


@app.route('/api/alerts/<int:alert_id>', methods=['GET', 'PUT'])
def api_alert_detail(alert_id):
    with app.app_context():
        alert = db.session.get(Alert, alert_id)
        if alert is None:
            return jsonify({'error': 'Not found'}), 404
        if request.method == 'PUT':
            data = request.get_json(silent=True) or {}
            if 'resolved' in data:
                alert.resolved = bool(data['resolved'])
                if data['resolved']:
                    from datetime import datetime
                    alert.resolution_time = datetime.now()
            if 'notes' in data:
                alert.notes = data['notes']
            db.session.commit()
        return jsonify(alert.to_dict())


@app.route('/api/alerts/<int:alert_id>/trace')
def api_alert_trace(alert_id):
    """
    Return the full trace for an alert:
      - trigger description
      - detection method breakdown
      - network flow context
      - feature snapshot
      - correlated alerts
    """
    with app.app_context():
        alert = db.session.get(Alert, alert_id)
        if alert is None:
            return jsonify({'error': 'Not found'}), 404

        # Parse stored context / trace
        raw_ctx = {}
        if alert.context:
            try:
                raw_ctx = json.loads(alert.context)
            except Exception:
                pass

        trace_block = raw_ctx.get('trace', {})
        flow_block  = raw_ctx.get('flow',  {})
        features    = raw_ctx.get('features_snapshot', {})
        asn         = raw_ctx.get('asn',   {})

        # Parse detection methods from description
        methods = _parse_detection_methods(alert.description or '')

        # Correlated alerts from same source
        from datetime import timedelta
        cutoff = alert.timestamp - timedelta(hours=24)
        correlated = (Alert.query
                      .filter(Alert.source_ip == alert.source_ip,
                              Alert.id        != alert.id,
                              Alert.timestamp  > cutoff)
                      .order_by(Alert.timestamp.desc())
                      .limit(10).all())

        return jsonify({
            'alert': alert.to_dict(),
            'trace': {
                'captured_at': trace_block.get('captured_at',
                               alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')),
                'trigger':     trace_block.get('trigger', alert.description),
                'risk_score':  alert.risk_score,
                'risk_level':  alert.risk_level,
            },
            'detection_methods': methods,
            'flow':     flow_block,
            'asn':      asn,
            'features': features,
            'correlated': [{
                'id':        a.id,
                'timestamp': a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'risk_level': a.risk_level,
                'risk_score': a.risk_score,
                'description': a.description,
                'resolved':   a.resolved,
            } for a in correlated],
        })


# ════════════════════════════════════════════════════════════════════════════
# API — system
# ════════════════════════════════════════════════════════════════════════════

@app.route('/api/system/status')
def api_system_status():
    with app.app_context():
        return jsonify({
            'capture_running':      capture_manager is not None and capture_manager.is_running(),
            'detection_running':    detection_engine is not None,
            'alert_manager_active': alert_manager is not None,
            'uptime_seconds':       time.time() - app.config.get('START_TIME', time.time()),
            'processed_packets':    capture_manager.get_total_packets() if capture_manager else 0,
            'total_alerts':         Alert.query.count(),
            'unresolved_alerts':    Alert.query.filter_by(resolved=False).count(),
        })


# ════════════════════════════════════════════════════════════════════════════
# Error handlers
# ════════════════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def err_404(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('404.html'), 404


@app.errorhandler(500)
def err_500(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500


# ════════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════════

def _parse_detection_methods(description: str) -> list:
    """Break the pipe-separated description into method dicts."""
    methods = []
    for part in description.split(' | '):
        part = part.strip()
        if not part:
            continue
        if part.startswith('Signature'):
            methods.append({'method': 'Signature', 'detail': part})
        elif part.startswith('ML'):
            methods.append({'method': 'ML', 'detail': part})
        elif part.startswith('Anomaly'):
            methods.append({'method': 'Anomaly', 'detail': part})
        elif 'offender' in part or 'flagged' in part or 'actor' in part:
            methods.append({'method': 'Reputation', 'detail': part})
        else:
            methods.append({'method': 'Other', 'detail': part})
    return methods


# ════════════════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════════════════

def main() -> None:
    app.config['START_TIME'] = time.time()
    logger.info('=== CIC-IDS starting ===')
    init_database()
    start_services()
    logger.info('Dashboard → http://localhost:%d', app.config['PORT'])
    app.run(
        host      = app.config['HOST'],
        port      = app.config['PORT'],
        debug     = app.config['DEBUG'],
        use_reloader = False,
    )


if __name__ == '__main__':
    main()
