import json
import logging
import os
import time

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix,
                              f1_score, precision_score, recall_score)
from sklearn.neural_network import MLPClassifier

from utils.dataset_loader import BENIGN_LABELS, CIC_LABEL_COL, CICIDSDataLoader

logger = logging.getLogger(__name__)


def train_models(app_config: dict, model_dir: str) -> dict | None:
    start = time.time()
    logger.info('Training models…')
    os.makedirs(model_dir, exist_ok=True)

    loader = CICIDSDataLoader(app_config['DATASET_PATH'])
    data   = loader.load_dataset(app_config.get('TRAINING_SAMPLE_SIZE', 100_000))
    if data is None or data.empty:
        logger.error('Dataset empty — check DATASET_PATH')
        return None

    X_tr, X_te, y_tr, y_te, scaler = loader.prepare_model_data(data)
    joblib.dump(scaler, os.path.join(model_dir, 'feature_scaler.pkl'))
    with open(os.path.join(model_dir, 'feature_names.txt'), 'w') as fh:
        fh.write('\n'.join(loader.feature_names))
    logger.info('Scaler + %d feature names saved', len(loader.feature_names))

    defs = {
        'random_forest': RandomForestClassifier(
            n_estimators=100, max_depth=20, min_samples_split=10,
            random_state=42, n_jobs=-1),
        'gradient_boosting': GradientBoostingClassifier(
            n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42),
        'neural_network': MLPClassifier(
            hidden_layer_sizes=(100, 50), max_iter=300,
            activation='relu', solver='adam', random_state=42),
    }

    results = {}
    for name, model in defs.items():
        logger.info('  Training %s…', name)
        t0 = time.time()
        model.fit(X_tr, y_tr)
        y_pred = model.predict(X_te)
        metrics = {
            'accuracy':         float(accuracy_score(y_te, y_pred)),
            'precision':        float(precision_score(y_te, y_pred, zero_division=0)),
            'recall':           float(recall_score(y_te, y_pred, zero_division=0)),
            'f1_score':         float(f1_score(y_te, y_pred, zero_division=0)),
            'confusion_matrix': confusion_matrix(y_te, y_pred).tolist(),
            'training_time':    round(time.time() - t0, 2),
        }
        path = os.path.join(model_dir, f'{name}_model.pkl')
        joblib.dump(model, path)
        results[name] = {'model': model, 'path': path, **metrics}
        logger.info('  %s  Acc=%.4f  F1=%.4f  (%.1fs)',
                    name, metrics['accuracy'], metrics['f1_score'], metrics['training_time'])

    logger.info('Training done in %.1fs', time.time() - start)
    return results


def generate_signatures(data, sig_dir: str) -> dict:
    os.makedirs(sig_dir, exist_ok=True)
    if 'is_attack' in data.columns:
        atk = data[data['is_attack'] == 1]
        ben = data[data['is_attack'] == 0]
        has_label = CIC_LABEL_COL in data.columns
    elif CIC_LABEL_COL in data.columns:
        atk = data[~data[CIC_LABEL_COL].astype(str).isin(BENIGN_LABELS)]
        ben = data[data[CIC_LABEL_COL].astype(str).isin(BENIGN_LABELS)]
        has_label = True
    else:
        logger.error('No label column found')
        return {}

    sigs = {}
    if has_label and data[CIC_LABEL_COL].dtype == object:
        for lbl in atk[CIC_LABEL_COL].unique():
            if str(lbl) in BENIGN_LABELS:
                continue
            sig = _build_sig(atk[atk[CIC_LABEL_COL] == lbl], ben, str(lbl))
            sigs[str(lbl)] = sig
    else:
        sigs['Generic'] = _build_sig(atk, ben, 'Generic Attack')

    for name, sig in sigs.items():
        safe = name.replace(' ', '_').replace('/', '-')
        with open(os.path.join(sig_dir, f'{safe}.json'), 'w') as fh:
            json.dump(sig, fh, indent=2)

    logger.info('%d signature(s) saved to %s', len(sigs), sig_dir)
    return sigs


def _build_sig(atk, ben, label):
    sig = {'name': label,
           'description': f'Auto-generated from {len(atk)} samples',
           'rules': []}
    for col in atk.select_dtypes(include=[np.number]).columns:
        if col in ('is_attack', 'Label'):
            continue
        try:
            am, bm = float(atk[col].mean()), float(ben[col].mean())
            as_, bs = float(atk[col].std(ddof=0)) or 1e-10, float(ben[col].std(ddof=0)) or 1e-10
            if abs(am - bm) > 2 * (as_ + bs) / 2:
                op  = '>' if am > bm else '<'
                thr = bm + 3*bs if am > bm else bm - 3*bs
                sig['rules'].append({
                    'feature':   col,
                    'operator':  op,
                    'threshold': round(float(thr), 6),
                    'weight':    round(abs(am - bm) / (bs + 1e-10), 4),
                })
        except Exception:
            continue
    sig['rules'] = sorted(sig['rules'], key=lambda r: r['weight'], reverse=True)[:10]
    return sig
