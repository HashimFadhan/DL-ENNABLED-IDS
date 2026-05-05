import math
from collections import Counter


def extract_tcp_flags(flags_byte) -> set:
    """Convert TCP flags byte → set of chars: F S R P A U E C"""
    flag_map = {0: 'F', 1: 'S', 2: 'R', 3: 'P', 4: 'A', 5: 'U', 6: 'E', 7: 'C'}
    result = set()
    try:
        val = int(flags_byte)
        for bit, ch in flag_map.items():
            if val & (1 << bit):
                result.add(ch)
    except (TypeError, ValueError):
        pass
    return result


def calculate_entropy(series) -> float:
    """Shannon entropy of an iterable. Returns 0.0 for empty input."""
    try:
        vals = list(series)
        if not vals:
            return 0.0
        total = len(vals)
        return -sum(
            (c / total) * math.log2(c / total)
            for c in Counter(vals).values()
        )
    except Exception:
        return 0.0
