#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
salt/token 生成对比实验：
- LCG(32-bit) -> 拼成 128-bit token/salt
- MT19937(Python random.Random) -> 拼成 128-bit
- OS CSPRNG -> secrets.token_bytes(16)

输出：
- 碰撞数 / 碰撞率
- 前缀碰撞（比如前 16/24/32 bit 的重复）——更容易看出“结构/预测风险”
- 最后一个 hex digit 的频数（简单边际分布检查）
- 相邻 token 低 16-bit 的 scatter（看相关性/条纹）
- 可选：演示“time-based seed 可被窗口穷举恢复”的玩具攻击

依赖：Python 3.9+，matplotlib
"""

import argparse
import secrets
import time
import random
from collections import Counter
from dataclasses import dataclass
from typing import List, Tuple, Optional

import matplotlib.pyplot as plt


# ---------------------------
# RNGs
# ---------------------------
class RNG32:
    """Return u32 in [0, 2^32-1]."""

    def next_u32(self) -> int:
        raise NotImplementedError


class LCG32(RNG32):
    """
    32-bit LCG: x_{n+1} = (a*x_n + c) mod 2^32
    Default parameters are common.
    """
    def __init__(self, seed: int, a: int = 1664525, c: int = 1013904223):
        self.state = seed & 0xFFFFFFFF
        self.a = a & 0xFFFFFFFF
        self.c = c & 0xFFFFFFFF

    def next_u32(self) -> int:
        self.state = (self.a * self.state + self.c) & 0xFFFFFFFF
        return self.state


class MT32(RNG32):
    """Python's MT19937"""
    def __init__(self, seed: int):
        self.r = random.Random(seed)

    def next_u32(self) -> int:
        return self.r.getrandbits(32)


def u32s_to_128(u32s: List[int]) -> int:
    """Combine 4x u32 into one 128-bit int (big-endian concatenation)."""
    if len(u32s) != 4:
        raise ValueError("need exactly 4 u32 words")
    x = 0
    for w in u32s:
        x = (x << 32) | (w & 0xFFFFFFFF)
    return x


def gen_tokens_lcg(n: int, seed: int, a: int, c: int) -> List[int]:
    rng = LCG32(seed=seed, a=a, c=c)
    out = []
    for _ in range(n):
        words = [rng.next_u32() for _ in range(4)]
        out.append(u32s_to_128(words))
    return out


def gen_tokens_mt(n: int, seed: int) -> List[int]:
    rng = MT32(seed=seed)
    out = []
    for _ in range(n):
        words = [rng.next_u32() for _ in range(4)]
        out.append(u32s_to_128(words))
    return out


def gen_tokens_csprng(n: int) -> List[int]:
    out = []
    for _ in range(n):
        b = secrets.token_bytes(16)
        out.append(int.from_bytes(b, byteorder="big", signed=False))
    return out


# ---------------------------
# Metrics
# ---------------------------
@dataclass
class Stats:
    name: str
    n: int
    collisions: int
    collision_rate: float
    prefix_collisions_16: int
    prefix_collisions_24: int
    prefix_collisions_32: int
    last_hex_digit_counts: Counter


def count_collisions(xs: List[int]) -> Tuple[int, float]:
    n = len(xs)
    uniq = len(set(xs))
    collisions = n - uniq
    return collisions, collisions / n if n else 0.0


def prefix_collision_count(xs: List[int], prefix_bits: int) -> int:
    """
    Count collisions after truncating to prefix_bits (high bits).
    E.g. prefix_bits=16 means keep top 16 bits of 128-bit token.
    """
    if prefix_bits <= 0 or prefix_bits > 128:
        raise ValueError("prefix_bits must be in 1..128")
    shift = 128 - prefix_bits
    pref = [(x >> shift) & ((1 << prefix_bits) - 1) for x in xs]
    return len(pref) - len(set(pref))


def last_hex_digit_freq(xs: List[int]) -> Counter:
    # last hex digit corresponds to low 4 bits
    return Counter((x & 0xF) for x in xs)


def compute_stats(name: str, xs: List[int]) -> Stats:
    col, col_rate = count_collisions(xs)
    p16 = prefix_collision_count(xs, 16)
    p24 = prefix_collision_count(xs, 24)
    p32 = prefix_collision_count(xs, 32)
    freq = last_hex_digit_freq(xs)
    return Stats(
        name=name,
        n=len(xs),
        collisions=col,
        collision_rate=col_rate,
        prefix_collisions_16=p16,
        prefix_collisions_24=p24,
        prefix_collisions_32=p32,
        last_hex_digit_counts=freq,
    )


# ---------------------------
# Plots
# ---------------------------
def plot_last_hex_digit(stats_list: List[Stats], out_path: str):
    # One plot per stats would be clearer, but keep one to compare quickly.
    # We'll plot counts for digits 0..15.
    digits = list(range(16))
    plt.figure()
    for st in stats_list:
        ys = [st.last_hex_digit_counts.get(d, 0) for d in digits]
        plt.plot(digits, ys, marker="o", label=st.name)  # no explicit colors
    plt.title("Last hex digit frequency (low 4 bits)")
    plt.xlabel("Hex digit (0..15)")
    plt.ylabel("Count")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()


def plot_scatter_low16(xs: List[int], title: str, out_path: str, max_points: int = 80000):
    # scatter of successive low-16 bits
    ys = [(x & 0xFFFF) for x in xs]
    if len(ys) > max_points:
        ys = ys[:max_points]
    if len(ys) < 2:
        return
    x1 = ys[:-1]
    x2 = ys[1:]
    plt.figure()
    plt.scatter(x1, x2, s=2)  # no explicit colors
    plt.title(title)
    plt.xlabel("low16(t)")
    plt.ylabel("low16(t+1)")
    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()


# ---------------------------
# Toy predictability demo (time-seeded PRNG)
# ---------------------------
def first_token_hex_from_time_seed(kind: str, seed: int, a: int, c: int) -> str:
    if kind == "lcg":
        xs = gen_tokens_lcg(1, seed=seed, a=a, c=c)
    elif kind == "mt":
        xs = gen_tokens_mt(1, seed=seed)
    else:
        raise ValueError("kind must be 'lcg' or 'mt'")
    return f"{xs[0]:032x}"


def brute_force_time_seed(kind: str, observed_hex: str, approx_time: int, window: int, a: int, c: int) -> Optional[int]:
    """
    Attacker knows token generated near approx_time (Unix seconds), tries seeds in [t-window, t+window].
    Returns recovered seed if found.
    """
    for s in range(approx_time - window, approx_time + window + 1):
        if first_token_hex_from_time_seed(kind, seed=s, a=a, c=c) == observed_hex:
            return s
    return None


# ---------------------------
# Main
# ---------------------------
def print_stats(st: Stats):
    # print in report-friendly way
    print(f"=== {st.name} ===")
    print(f"N tokens: {st.n}")
    print(f"Exact collisions: {st.collisions} (rate={st.collision_rate:.6f})")
    print(f"Prefix collisions (top 16 bits): {st.prefix_collisions_16}")
    print(f"Prefix collisions (top 24 bits): {st.prefix_collisions_24}")
    print(f"Prefix collisions (top 32 bits): {st.prefix_collisions_32}")
    # low 4-bit frequency summary (max/min)
    counts = [st.last_hex_digit_counts.get(d, 0) for d in range(16)]
    print(f"Last-hex-digit count min/max: {min(counts)} / {max(counts)}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Salt/Token generation audit: LCG vs MT vs OS CSPRNG")
    ap.add_argument("--n", type=int, default=200000, help="How many 128-bit tokens/salts to generate per RNG")
    ap.add_argument("--seed", type=int, default=1, help="Seed for LCG/MT (fixed-seed experiment)")
    ap.add_argument("--lcg_a", type=int, default=1664525)
    ap.add_argument("--lcg_c", type=int, default=1013904223)
    ap.add_argument("--out_prefix", type=str, default="salt_token")
    ap.add_argument("--no_mt", action="store_true", help="Skip MT (only LCG vs CSPRNG)")
    ap.add_argument("--no_plots", action="store_true", help="Skip saving plots")
    ap.add_argument("--demo_time_seed", action="store_true", help="Run toy demo: time-seeded predictability attack")
    ap.add_argument("--time_window", type=int, default=30, help="Brute-force window in seconds for time-seed demo")
    args = ap.parse_args()

    # 1) Generate tokens
    xs_lcg = gen_tokens_lcg(args.n, seed=args.seed, a=args.lcg_a, c=args.lcg_c)
    xs_csp = gen_tokens_csprng(args.n)

    stats_list = [compute_stats("LCG(128 via 4x u32)", xs_lcg)]

    if not args.no_mt:
        xs_mt = gen_tokens_mt(args.n, seed=args.seed)
        stats_list.append(compute_stats("MT19937(128 via 4x u32)", xs_mt))
    else:
        xs_mt = None

    stats_list.append(compute_stats("OS CSPRNG (secrets.token_bytes)", xs_csp))

    # 2) Print stats
    for st in stats_list:
        print_stats(st)

    # 3) Save plots
    if not args.no_plots:
        plot_last_hex_digit(stats_list, f"{args.out_prefix}_lasthex.png")
        plot_scatter_low16(xs_lcg, "LCG: scatter of successive low16", f"{args.out_prefix}_lcg_scatter.png")
        if xs_mt is not None:
            plot_scatter_low16(xs_mt, "MT19937: scatter of successive low16", f"{args.out_prefix}_mt_scatter.png")
        plot_scatter_low16(xs_csp, "OS CSPRNG: scatter of successive low16", f"{args.out_prefix}_csprng_scatter.png")
        print(f"Saved plots: {args.out_prefix}_*.png")

    # 4) Toy time-seed predictability demo
    if args.demo_time_seed:
        print("\n=== Toy demo: time-seeded predictability (for report illustration) ===")
        t = int(time.time())
        for kind in ["lcg", "mt"]:
            observed = first_token_hex_from_time_seed(kind, seed=t, a=args.lcg_a, c=args.lcg_c)
            recovered = brute_force_time_seed(
                kind=kind,
                observed_hex=observed,
                approx_time=t,
                window=args.time_window,
                a=args.lcg_a,
                c=args.lcg_c,
            )
            print(f"[{kind}] observed token (first, hex): {observed}")
            if recovered is None:
                print(f"[{kind}] seed not found within ±{args.time_window}s (unexpected in this toy setting)")
            else:
                print(f"[{kind}] recovered seed within ±{args.time_window}s: {recovered}")
        print("Note: This demo shows why 'time as seed' is dangerous for tokens/salts; use OS CSPRNG instead.")


if __name__ == "__main__":
    main()
