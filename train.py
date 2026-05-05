"""
Standalone training script.

Usage:
    python train.py
    python train.py --sample 200000
    python train.py --signatures-only
"""
import argparse
import logging
import os
import sys

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s  %(levelname)-8s  %(message)s')
logger = logging.getLogger(__name__)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dataset',    default=os.path.join(BASE_DIR, 'data', 'cic_ids2018'))
    p.add_argument('--sample',     type=int, default=100_000)
    p.add_argument('--model-dir',  default=os.path.join(BASE_DIR, 'data', 'ml_models'))
    p.add_argument('--sig-dir',    default=os.path.join(BASE_DIR, 'data', 'signatures'))
    p.add_argument('--signatures-only', action='store_true')
    args = p.parse_args()

    os.makedirs(args.model_dir, exist_ok=True)
    os.makedirs(args.sig_dir,   exist_ok=True)

    from utils.dataset_loader import CICIDSDataLoader
    from modules.trainer import train_models, generate_signatures

    loader = CICIDSDataLoader(args.dataset)
    data   = loader.load_dataset(sample_size=args.sample)
    if data is None:
        logger.error('Failed to load dataset from: %s', args.dataset)
        sys.exit(1)

    if not args.signatures_only:
        cfg = {'DATASET_PATH': args.dataset,
               'TRAINING_SAMPLE_SIZE': args.sample}
        results = train_models(cfg, model_dir=args.model_dir)
        if not results:
            logger.error('Training failed')
            sys.exit(1)
        print('\n=== Model Results ===')
        for name, r in results.items():
            print(f'  {name:<22}  Acc={r["accuracy"]:.4f}  '
                  f'F1={r["f1_score"]:.4f}  '
                  f'Prec={r["precision"]:.4f}  '
                  f'Rec={r["recall"]:.4f}  '
                  f'({r["training_time"]:.1f}s)')

    sigs = generate_signatures(data, sig_dir=args.sig_dir)
    print(f'\nGenerated {len(sigs)} signature(s): {list(sigs.keys())}')
    print('\nDone. Run: python app.py')


if __name__ == '__main__':
    main()
