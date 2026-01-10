import argparse
import math
import random
from dataclasses import dataclass
from typing import List, Tuple, Optional

import matplotlib.pyplot as plt


# -----------------------------
# RNG interface + implementations
# -----------------------------
class RNG32:
    """Base class: must provide next_u32() -> int in [0, 2^32-1]."""

    def next_u32(self) -> int:
        raise NotImplementedError

    def randbelow(self, bound: int) -> int:
        """Unbiased integer in [0, bound-1] via rejection sampling."""
        if bound <= 0:
            raise ValueError("bound must be positive")
        # Use 32-bit space for rejection
        # Accept u in [0, limit) where limit is multiple of bound
        # limit = floor(2^32 / bound) * bound
        limit = (1 << 32) // bound * bound
        while True:
            u = self.next_u32()
            if u < limit:
                return u % bound


class LCG32(RNG32):
    """
    32-bit LCG: x_{n+1} = (a*x_n + c) mod 2^32
    Default parameters are common (Numerical Recipes style).
    """
    def __init__(self, seed: int, a: int = 1664525, c: int = 1013904223):
        self.state = seed & 0xFFFFFFFF
        self.a = a & 0xFFFFFFFF
        self.c = c & 0xFFFFFFFF

    def next_u32(self) -> int:
        self.state = (self.a * self.state + self.c) & 0xFFFFFFFF
        return self.state


class MT32(RNG32):
    """Python's Mersenne Twister via random.Random(seed).getrandbits(32)."""
    def __init__(self, seed: int):
        self.r = random.Random(seed)

    def next_u32(self) -> int:
        return self.r.getrandbits(32)


# -----------------------------
# Sampling without replacement (partial Fisher–Yates via dict mapping)
# -----------------------------
def draw_k_unique_via_mapping(rng: RNG32, n: int, k: int, j_trace: Optional[List[int]] = None) -> List[int]:
    """
    Sample k unique winners from [0..n-1] uniformly without building list(range(n)).
    Implements partial Fisher–Yates using a sparse mapping dict.
    Complexity: O(k), memory: O(k).
    """
    if not (0 < k <= n):
        raise ValueError("Require 0 < k <= n")

    mapping = {}  # position -> value (after swaps)
    winners = []

    def get(pos: int) -> int:
        return mapping.get(pos, pos)

    for i in range(k):
        # choose j uniformly in [i, n-1]
        j = i + rng.randbelow(n - i)
        if j_trace is not None:
            j_trace.append(j)

        vi = get(i)
        vj = get(j)
        # swap positions i and j
        mapping[i] = vj
        mapping[j] = vi
        winners.append(vj)  # after swap, position i holds vj

    return winners


# -----------------------------
# Metrics + plots
# -----------------------------
@dataclass
class AuditResult:
    name: str
    win_count: List[int]
    j_trace: List[int]
    mean: float
    std: float
    minv: int
    maxv: int
    chi2: float
    bucket_counts: List[int]
    exact_duplicate_rate: float
    near_duplicate_rate: float


def bucketize_counts(win_count: List[int], buckets: int) -> List[int]:
    n = len(win_count)
    if n % buckets != 0:
        raise ValueError("For simplicity, require n divisible by buckets")
    size = n // buckets
    out = []
    for b in range(buckets):
        s = sum(win_count[b * size:(b + 1) * size])
        out.append(s)
    return out


def chi_square(observed: List[int], expected: float) -> float:
    # expected is same for each bucket
    return sum(((o - expected) ** 2) / expected for o in observed)


def duplicate_rates(starts: List[int], eps: float = 0.0) -> Tuple[float, float]:
    """
    Exact duplicates and near-duplicates for a numeric sequence.
    If eps=0: near duplicates equals exact duplicates.
    If eps>0: counts pairs (adjacent in sorted order) within eps.
    """
    n = len(starts)
    if n == 0:
        return 0.0, 0.0

    # exact duplicates
    s_sorted = sorted(starts)
    exact_dup = 0
    for i in range(1, n):
        if s_sorted[i] == s_sorted[i - 1]:
            exact_dup += 1
    exact_rate = exact_dup / n

    if eps <= 0:
        return exact_rate, exact_rate

    near_dup = 0
    for i in range(1, n):
        if abs(s_sorted[i] - s_sorted[i - 1]) <= eps:
            near_dup += 1
    near_rate = near_dup / n
    return exact_rate, near_rate


def summarize(win_count: List[int]) -> Tuple[float, float, int, int]:
    n = len(win_count)
    mean = sum(win_count) / n
    var = sum((x - mean) ** 2 for x in win_count) / n
    std = math.sqrt(var)
    return mean, std, min(win_count), max(win_count)


def run_audit(name: str, rng: RNG32, n: int, k: int, rounds: int, buckets: int, scatter_points: int) -> AuditResult:
    win_count = [0] * n
    j_trace: List[int] = []

    # run R rounds
    for _ in range(rounds):
        winners = draw_k_unique_via_mapping(rng, n, k, j_trace=j_trace)
        for w in winners:
            win_count[w] += 1

    mean, std, minv, maxv = summarize(win_count)

    bucket_counts = bucketize_counts(win_count, buckets=buckets)
    expected_bucket = rounds * k * (n // buckets) / n  # = rounds*k/buckets
    chi2 = chi_square(bucket_counts, expected_bucket)

    # For duplicates, use j_trace (the raw random indices chosen during sampling)
    # Exact duplicates are possible because j ranges vary; near duplicates are meaningful too.
    exact_rate, near_rate = duplicate_rates(j_trace, eps=1.0)  # within 1 index

    # truncate trace for scatter plot
    if scatter_points > 0 and len(j_trace) > scatter_points:
        j_trace_plot = j_trace[:scatter_points]
    else:
        j_trace_plot = j_trace

    return AuditResult(
        name=name,
        win_count=win_count,
        j_trace=j_trace_plot,
        mean=mean,
        std=std,
        minv=minv,
        maxv=maxv,
        chi2=chi2,
        bucket_counts=bucket_counts,
        exact_duplicate_rate=exact_rate,
        near_duplicate_rate=near_rate,
    )


def plot_results(res_a: AuditResult, res_b: AuditResult, n: int, k: int, rounds: int, buckets: int, out_prefix: str):
    # 1) Histogram of win_count
    def plot_hist(res: AuditResult, path: str):
        maxc = max(res.win_count)
        bins = range(0, maxc + 2)  # integer bins
        plt.figure()
        plt.hist(res.win_count, bins=bins, edgecolor="black", linewidth=0.5)
        plt.title(f"{res.name}: Win-count distribution (n={n}, k={k}, rounds={rounds})")
        plt.xlabel("Wins per person")
        plt.ylabel("Number of people")
        plt.tight_layout()
        plt.savefig(path, dpi=200)
        plt.close()

    # 2) Bucket bar chart
    def plot_buckets(res: AuditResult, path: str):
        plt.figure()
        plt.bar(range(buckets), res.bucket_counts)
        plt.title(f"{res.name}: Bucketed total wins (buckets={buckets})")
        plt.xlabel("Bucket index")
        plt.ylabel("Total wins in bucket")
        plt.tight_layout()
        plt.savefig(path, dpi=200)
        plt.close()

    # 3) Scatter of successive j values
    def plot_scatter(res: AuditResult, path: str):
        xs = res.j_trace[:-1]
        ys = res.j_trace[1:]
        plt.figure()
        plt.scatter(xs, ys, s=2)
        plt.title(f"{res.name}: Scatter of successive indices (j_t, j_(t+1))")
        plt.xlabel("j_t")
        plt.ylabel("j_(t+1)")
        plt.tight_layout()
        plt.savefig(path, dpi=200)
        plt.close()

    plot_hist(res_a, f"{out_prefix}_{res_a.name}_hist.png")
    plot_hist(res_b, f"{out_prefix}_{res_b.name}_hist.png")

    plot_buckets(res_a, f"{out_prefix}_{res_a.name}_buckets.png")
    plot_buckets(res_b, f"{out_prefix}_{res_b.name}_buckets.png")

    plot_scatter(res_a, f"{out_prefix}_{res_a.name}_scatter.png")
    plot_scatter(res_b, f"{out_prefix}_{res_b.name}_scatter.png")


def print_summary(res: AuditResult, n: int, k: int, rounds: int, buckets: int):
    expected_mean = rounds * (k / n)
    expected_bucket = rounds * k / buckets
    print(f"=== {res.name} ===")
    print(f"Expected mean wins/person: {expected_mean:.6f}")
    print(f"Observed mean wins/person: {res.mean:.6f}")
    print(f"Observed std wins/person : {res.std:.6f}")
    print(f"Min/Max wins/person      : {res.minv} / {res.maxv}")
    print(f"Chi-square (bucketed)    : {res.chi2:.3f}  (expected per-bucket {expected_bucket:.3f})")
    print(f"Index exact dup rate     : {res.exact_duplicate_rate:.6f}")
    print(f"Index near dup rate (±1) : {res.near_duplicate_rate:.6f}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Lottery fairness audit: LCG vs MT19937")
    ap.add_argument("--n", type=int, default=10000)
    ap.add_argument("--k", type=int, default=100)
    ap.add_argument("--rounds", type=int, default=2000)
    ap.add_argument("--buckets", type=int, default=100)
    ap.add_argument("--seed", type=int, default=123456789)
    ap.add_argument("--scatter_points", type=int, default=80000, help="How many j values to keep for scatter")
    ap.add_argument("--out_prefix", type=str, default="audit")
    # LCG params (change to match your report if needed)
    ap.add_argument("--lcg_a", type=int, default=1664525)
    ap.add_argument("--lcg_c", type=int, default=1013904223)

    args = ap.parse_args()

    if args.n % args.buckets != 0:
        raise SystemExit("Require n divisible by buckets (for simple bucketization).")

    lcg = LCG32(seed=args.seed, a=args.lcg_a, c=args.lcg_c)
    mt = MT32(seed=args.seed)  # same seed for fairness / reproducibility

    res_lcg = run_audit("LCG", lcg, args.n, args.k, args.rounds, args.buckets, args.scatter_points)
    res_mt = run_audit("MT", mt, args.n, args.k, args.rounds, args.buckets, args.scatter_points)

    print_summary(res_lcg, args.n, args.k, args.rounds, args.buckets)
    print_summary(res_mt, args.n, args.k, args.rounds, args.buckets)

    plot_results(res_lcg, res_mt, args.n, args.k, args.rounds, args.buckets, args.out_prefix)
    print(f"Saved plots with prefix: {args.out_prefix}_*.png")


if __name__ == "__main__":
    main()
