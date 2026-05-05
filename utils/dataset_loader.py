import glob
import logging
import os

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

CIC_LABEL_COL   = 'Label'
BENIGN_LABELS   = {'Benign', 'BENIGN', 'benign', '0', 0}
NON_FEATURE_COLS = {
    'Label', 'Timestamp', 'Src IP', 'Dst IP', 'Flow ID', 'External IP', 'is_attack',
}


class CICIDSDataLoader:

    def __init__(self, dataset_path: str):
        self.dataset_path  = dataset_path
        self.feature_names = []

    def load_dataset(self, sample_size: int = 100_000):
        csvs = glob.glob(os.path.join(self.dataset_path, '**', '*.csv'), recursive=True)
        if not csvs:
            logger.error('No CSV files in %s', self.dataset_path)
            return None

        logger.info('Found %d CSV file(s)', len(csvs))
        per_file = max(1, sample_size // len(csvs))
        chunks   = []

        for path in csvs:
            try:
                df = pd.read_csv(path, nrows=per_file, low_memory=False,
                                 encoding='utf-8', on_bad_lines='skip')
                df.columns = df.columns.str.strip()
                chunks.append(df)
                logger.info('  %s  →  %d rows', os.path.basename(path), len(df))
            except Exception as exc:
                logger.warning('Skip %s: %s', path, exc)

        if not chunks:
            return None

        data = pd.concat(chunks, ignore_index=True)
        data = self._clean(data)
        logger.info('Dataset ready: %d rows × %d cols', *data.shape)
        return data

    def prepare_model_data(self, data: pd.DataFrame):
        if 'is_attack' in data.columns:
            y = data['is_attack'].astype(int)
        elif CIC_LABEL_COL in data.columns:
            y = data[CIC_LABEL_COL].apply(
                lambda v: 0 if str(v).strip() in BENIGN_LABELS else 1
            ).astype(int)
        else:
            raise ValueError('No label column found.')

        drop = [c for c in NON_FEATURE_COLS if c in data.columns]
        X = (data.drop(columns=drop, errors='ignore')
                 .select_dtypes(include=[np.number])
                 .replace([np.inf, -np.inf], np.nan)
                 .fillna(0))

        self.feature_names = list(X.columns)
        logger.info('Features: %d  |  Attack ratio: %.2f%%',
                    len(self.feature_names), y.mean()*100)

        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y)

        scaler = StandardScaler()
        return scaler.fit_transform(X_tr), scaler.transform(X_te), y_tr, y_te, scaler

    @staticmethod
    def _clean(df: pd.DataFrame) -> pd.DataFrame:
        num = df.select_dtypes(include=[np.number]).columns
        if len(num):
            df[num] = df[num].replace([np.inf, -np.inf], np.nan)
            df = df.dropna(subset=num, how='all')
        return df.reset_index(drop=True)
