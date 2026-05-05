import os
import secrets

# Absolute base directory (folder where this file lives)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Create data directory immediately so nothing else fails on import
os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)


class Config:
    # ── Flask ──────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(16))
    DEBUG      = os.environ.get('DEBUG', 'False').lower() == 'true'
    HOST       = os.environ.get('HOST', '0.0.0.0')
    PORT       = int(os.environ.get('PORT', 5000))

    # ── Database (absolute path so SQLite always finds it) ─────────────
    _DB_PATH = os.path.join(BASE_DIR, 'data', 'ids.db')
    SQLALCHEMY_DATABASE_URI    = os.environ.get('DATABASE_URI',
                                                f'sqlite:///{_DB_PATH}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── Dataset ────────────────────────────────────────────────────────
    DATASET_PATH          = os.environ.get('DATASET_PATH',
                                           os.path.join(BASE_DIR, 'data', 'cic_ids2018'))
    TRAINING_SAMPLE_SIZE  = int(os.environ.get('TRAINING_SAMPLE_SIZE', 100000))

    # ── Capture ────────────────────────────────────────────────────────
    DEFAULT_INTERFACE   = os.environ.get('CAPTURE_INTERFACE', None)
    PACKET_BUFFER_SIZE  = int(os.environ.get('PACKET_BUFFER_SIZE', 1000))

    # ── Detection ──────────────────────────────────────────────────────
    ALERT_THRESHOLD      = int(os.environ.get('ALERT_THRESHOLD', 3))
    ML_DETECTION         = os.environ.get('ML_DETECTION',        'True').lower() == 'true'
    SIGNATURE_DETECTION  = os.environ.get('SIGNATURE_DETECTION', 'True').lower() == 'true'
    ANOMALY_DETECTION    = os.environ.get('ANOMALY_DETECTION',   'True').lower() == 'true'
