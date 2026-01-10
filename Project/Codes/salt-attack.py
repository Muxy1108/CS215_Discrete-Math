# -*- coding: utf-8 -*-
"""
Salt/Token 生成对比实验（统计 + 攻击视角，尽可能全都加进去）

对比随机源：
- LCG(32-bit) -> 4×u32 拼成 128-bit token/salt
- MT19937(Python random.Random) -> 4×u32 拼成 128-bit
- OS CSPRNG -> secrets.token_bytes(16)

统计输出（report-friendly）：
1) 128-bit token 的精确碰撞（exact collisions）
2) 高位前缀碰撞：top 16 / 24 / 32 bits
3) token 低 4 bit（最后一个 hex digit）的频数 min/max + 计数表
4) “每个 token 的 4 个 u32 分别统计低 4 bit”（用于解释 LCG 的 step-sampling 现象）
5) 相邻相关性散点图：
   - token 的 low16(t) vs low16(t+1)
   - （可选）每个 word 位置的 low16 scatter（更强的结构展示）

攻击视角演示（Toy，但闭环）：
A) time-seeded 攻击（seed recovery + 预测 token#2 并验证成功）
   - 受害者用 Unix 秒作 seed，生成 token#1 和 token#2
   - 攻击者知道大概时间窗口 ±W 秒，穷举 seed 匹配 token#1
   - 恢复 seed 后预测 token#2，并与真实 token#2 对比

B) LCG 参数恢复（从 3 个连续 u32 输出恢复 a,c 并预测下一输出）
   - 若 (x1-x0) 在 mod 2^32 下可逆（即为奇数），可直接恢复
   - 该 demo 用于证明“线性结构可被利用”，从统计偏差落到可预测性

依赖：
- Python 3.9+
- matplotlib（仅用于出图；没有也能跑统计/攻击，自动跳过出图）
"""

import argparse
import secrets
import time
import random
from collections import Counter
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict


# ---------------------------
# Optional matplotlib
# ---------------------------
try:
    import matplotlib.pyplot as plt
    HAS_MPL = True
except Exception:
    HAS_MPL = False


# ---------------------------
# RNGs
# ---------------------------
MASK32 = 0xFFFFFFFF
MOD32 = 1 << 32


class RNG32:
    """Return u32 in [0, 2^32-1]."""
    def next_u32(self) -> int:
        raise NotImplementedError


class LCG32(RNG32):
    """
    32-bit LCG: x_{n+1} = (a*x_n + c) mod 2^32
    """
    def __init__(self, seed: int, a: int = 1664525, c: int = 1013904223):
        self.state = seed & MASK32
        self.a = a & MASK32
        self.c = c & MASK32

    def next_u32(self) -> int:
        self.state = (self.a * self.state + self.c) & MASK32
        return self.state


class MT32(RNG32):
    """Python MT19937"""
    def __init__(self, seed: int):
        self.r = random.Random(seed)

    def next_u32(self) -> int:
        return self.r.getrandbits(32)


# ---------------------------
# Token construction + raw word capture
# ---------------------------
def u32s_to_128(words: List[int]) -> int:
    """Big-endian concat of 4×u32 -> 128-bit int."""
    if len(words) != 4:
        raise ValueError("need exactly 4 u32 words")
    x = 0
    for w in words:
        x = (x << 32) | (w & MASK32)
    return x


def token_hex(x128: int) -> str:
    return f"{x128:032x}"


def gen_tokens_from_rng(n: int, rng: RNG32) -> Tuple[List[int], List[List[int]]]:
    """
    Generate n tokens.
    Returns:
      tokens: List[int]   (128-bit)
      words_per_token: List[List[int]]  each is length 4
    """
    tokens: List[int] = []
    words_per_token: List[List[int]] = []
    for _ in range(n):
        words = [rng.next_u32() for _ in range(4)]
        words_per_token.append(words)
        tokens.append(u32s_to_128(words))
    return tokens, words_per_token


def gen_tokens_lcg(n: int, seed: int, a: int, c: int) -> Tuple[List[int], List[List[int]]]:
    return gen_tokens_from_rng(n, LCG32(seed=seed, a=a, c=c))


def gen_tokens_mt(n: int, seed: int) -> Tuple[List[int], List[List[int]]]:
    return gen_tokens_from_rng(n, MT32(seed=seed))


def gen_tokens_csprng(n: int) -> Tuple[List[int], List[List[int]]]:
    tokens: List[int] = []
    words_per_token: List[List[int]] = []
    for _ in range(n):
        b = secrets.token_bytes(16)
        x128 = int.from_bytes(b, "big", signed=False)
        tokens.append(x128)
        # also provide word decomposition for uniform interface
        w0 = (x128 >> 96) & MASK32
        w1 = (x128 >> 64) & MASK32
        w2 = (x128 >> 32) & MASK32
        w3 = x128 & MASK32
        words_per_token.append([w0, w1, w2, w3])
    return tokens, words_per_token


# ---------------------------
# Metrics
# ---------------------------
@dataclass
class Stats:
    name: str
    n: int
    collisions_128: int
    collision_rate_128: float
    prefix_collisions_16: int
    prefix_collisions_24: int
    prefix_collisions_32: int

    lasthex_min: int
    lasthex_max: int
    lasthex_counts: Counter

    # per-word last hex (4 positions)
    word_lasthex_minmax: List[Tuple[int, int]]
    word_lasthex_counts: List[Counter]


def count_collisions(xs: List[int]) -> Tuple[int, float]:
    n = len(xs)
    uniq = len(set(xs))
    col = n - uniq
    return col, (col / n if n else 0.0)


def prefix_collision_count(tokens: List[int], prefix_bits: int) -> int:
    if prefix_bits <= 0 or prefix_bits > 128:
        raise ValueError("prefix_bits must be in 1..128")
    shift = 128 - prefix_bits
    pref = [(t >> shift) & ((1 << prefix_bits) - 1) for t in tokens]
    return len(pref) - len(set(pref))


def last_hex_digit_counts_128(tokens: List[int]) -> Counter:
    return Counter((t & 0xF) for t in tokens)


def last_hex_digit_counts_words(words_per_token: List[List[int]], pos: int) -> Counter:
    # pos in {0,1,2,3}
    return Counter((w[pos] & 0xF) for w in words_per_token)


def compute_stats(name: str, tokens: List[int], words_per_token: List[List[int]]) -> Stats:
    col128, colrate = count_collisions(tokens)
    p16 = prefix_collision_count(tokens, 16)
    p24 = prefix_collision_count(tokens, 24)
    p32 = prefix_collision_count(tokens, 32)

    lasthex = last_hex_digit_counts_128(tokens)
    lasthex_min = min(lasthex.get(d, 0) for d in range(16))
    lasthex_max = max(lasthex.get(d, 0) for d in range(16))

    word_counts: List[Counter] = []
    word_minmax: List[Tuple[int, int]] = []
    for pos in range(4):
        c = last_hex_digit_counts_words(words_per_token, pos)
        word_counts.append(c)
        mn = min(c.get(d, 0) for d in range(16))
        mx = max(c.get(d, 0) for d in range(16))
        word_minmax.append((mn, mx))

    return Stats(
        name=name,
        n=len(tokens),
        collisions_128=col128,
        collision_rate_128=colrate,
        prefix_collisions_16=p16,
        prefix_collisions_24=p24,
        prefix_collisions_32=p32,
        lasthex_min=lasthex_min,
        lasthex_max=lasthex_max,
        lasthex_counts=lasthex,
        word_lasthex_minmax=word_minmax,
        word_lasthex_counts=word_counts,
    )


def fmt_counter_0_15(c: Counter) -> str:
    # compact "0:123 1:456 ... 15:789"
    parts = []
    for d in range(16):
        parts.append(f"{d:>2}:{c.get(d,0)}")
    return " ".join(parts)


# ---------------------------
# Plots
# ---------------------------
def plot_last_hex_digit(stats_list: List[Stats], out_path: str) -> None:
    if not HAS_MPL:
        return
    digits = list(range(16))
    plt.figure()
    for st in stats_list:
        ys = [st.lasthex_counts.get(d, 0) for d in digits]
        plt.plot(digits, ys, marker="o", label=st.name)  # no explicit colors
    plt.title("Last hex digit frequency (low 4 bits of 128-bit token)")
    plt.xlabel("Hex digit (0..15)")
    plt.ylabel("Count")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()


def plot_last_hex_digit_per_word(stats: Stats, out_path: str) -> None:
    if not HAS_MPL:
        return
    digits = list(range(16))
    plt.figure()
    for pos in range(4):
        c = stats.word_lasthex_counts[pos]
        ys = [c.get(d, 0) for d in digits]
        plt.plot(digits, ys, marker="o", label=f"word[{pos}]")  # no explicit colors
    plt.title(f"{stats.name}: last hex digit per 32-bit word (low 4 bits)")
    plt.xlabel("Hex digit (0..15)")
    plt.ylabel("Count")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()


def plot_scatter_low16_from_tokens(tokens: List[int], title: str, out_path: str, max_points: int = 80000) -> None:
    if not HAS_MPL:
        return
    ys = [(t & 0xFFFF) for t in tokens]
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


def plot_scatter_low16_per_word(words_per_token: List[List[int]], title_prefix: str, out_prefix: str, max_points: int = 80000) -> None:
    if not HAS_MPL:
        return
    # build 4 streams, each is the low16 of that word position across tokens
    for pos in range(4):
        stream = [(w[pos] & 0xFFFF) for w in words_per_token]
        if len(stream) > max_points:
            stream = stream[:max_points]
        if len(stream) < 2:
            continue
        x1 = stream[:-1]
        x2 = stream[1:]
        plt.figure()
        plt.scatter(x1, x2, s=2)  # no explicit colors
        plt.title(f"{title_prefix}: word[{pos}] scatter of successive low16")
        plt.xlabel("low16(t)")
        plt.ylabel("low16(t+1)")
        plt.tight_layout()
        plt.savefig(f"{out_prefix}_word{pos}_scatter.png", dpi=200)
        plt.close()


# ---------------------------
# Attack demos
# ---------------------------
def two_tokens_hex_from_seed(kind: str, seed: int, a: int, c: int) -> Tuple[str, str]:
    """Generate token#1 and token#2 from a given seed (closed loop)."""
    if kind == "lcg":
        rng = LCG32(seed=seed, a=a, c=c)
        t1 = u32s_to_128([rng.next_u32() for _ in range(4)])
        t2 = u32s_to_128([rng.next_u32() for _ in range(4)])
    elif kind == "mt":
        rng = MT32(seed=seed)
        t1 = u32s_to_128([rng.next_u32() for _ in range(4)])
        t2 = u32s_to_128([rng.next_u32() for _ in range(4)])
    else:
        raise ValueError("kind must be 'lcg' or 'mt'")
    return token_hex(t1), token_hex(t2)


def brute_force_time_seed_and_predict(kind: str, observed_t1_hex: str, approx_time: int, window: int, a: int, c: int) -> Optional[Tuple[int, str]]:
    """Recover seed within [t-window, t+window] by matching token#1, then predict token#2."""
    for s in range(approx_time - window, approx_time + window + 1):
        cand1, cand2 = two_tokens_hex_from_seed(kind, seed=s, a=a, c=c)
        if cand1 == observed_t1_hex:
            return s, cand2
    return None


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def inv_mod_2_32(x: int) -> Optional[int]:
    """Inverse modulo 2^32 exists iff x is odd."""
    x &= MASK32
    if (x & 1) == 0:
        return None
    g, a, _ = egcd(x, MOD32)
    if g != 1:
        return None
    return a % MOD32


def recover_lcg_params_from_3_outputs(x0: int, x1: int, x2: int) -> Optional[Tuple[int, int]]:
    """
    x1 = a*x0 + c (mod 2^32)
    x2 = a*x1 + c (mod 2^32)
    => (x2-x1) = a*(x1-x0) (mod 2^32)
    If (x1-x0) invertible, recover a and c.
    """
    d1 = (x1 - x0) & MASK32
    d2 = (x2 - x1) & MASK32
    inv = inv_mod_2_32(d1)
    if inv is None:
        return None
    a_hat = (d2 * inv) & MASK32
    c_hat = (x1 - (a_hat * x0)) & MASK32
    return a_hat, c_hat


def demo_lcg_param_recovery(true_seed: int, true_a: int, true_c: int, max_tries: int = 20) -> None:
    """
    Demo B: if a single seed fails (because d1 even), try nearby seeds automatically.
    This produces a reliable “attack success” log for report.
    """
    print("\n=== Attack demo B: LCG parameter recovery from 3 outputs (toy) ===")
    for attempt in range(max_tries):
        seed = true_seed + attempt
        rng = LCG32(seed=seed, a=true_a, c=true_c)
        x0 = rng.next_u32()
        x1 = rng.next_u32()
        x2 = rng.next_u32()
        x3_true = rng.next_u32()

        rec = recover_lcg_params_from_3_outputs(x0, x1, x2)
        if rec is None:
            continue

        a_hat, c_hat = rec
        x3_hat = (a_hat * x2 + c_hat) & MASK32
        print(f"Victim seed used (for demo) : {seed}")
        print(f"Leaked outputs: x0={x0}, x1={x1}, x2={x2}")
        print(f"Recovered (a_hat, c_hat)   : ({a_hat}, {c_hat})")
        print(f"True      (a, c)           : ({true_a & MASK32}, {true_c & MASK32})")
        print(f"Predict next x3_hat         : {x3_hat}")
        print(f"Actual  next x3_true        : {x3_true}")
        print(f"Prediction success          : {x3_hat == x3_true}")
        return

    print(f"Recovery did not succeed within {max_tries} tries (rare). Try increasing --lcg_recover_tries or changing --seed.")


# ---------------------------
# Printing helpers
# ---------------------------
def print_stats(st: Stats, verbose_counts: bool = False) -> None:
    print(f"=== {st.name} ===")
    print(f"N tokens: {st.n}")
    print(f"Exact collisions (128-bit) : {st.collisions_128} (rate={st.collision_rate_128:.6f})")
    print(f"Prefix collisions (top 16): {st.prefix_collisions_16}")
    print(f"Prefix collisions (top 24): {st.prefix_collisions_24}")
    print(f"Prefix collisions (top 32): {st.prefix_collisions_32}")
    print(f"Last-hex-digit min/max     : {st.lasthex_min} / {st.lasthex_max}")

    # per-word min/max
    for pos in range(4):
        mn, mx = st.word_lasthex_minmax[pos]
        print(f"Word[{pos}] last-hex min/max: {mn} / {mx}")

    if verbose_counts:
        print("Last-hex counts (token low 4 bits):")
        print(fmt_counter_0_15(st.lasthex_counts))
        for pos in range(4):
            print(f"Word[{pos}] last-hex counts:")
            print(fmt_counter_0_15(st.word_lasthex_counts[pos]))
    print()


# ---------------------------
# Main
# ---------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="Salt/Token generation audit: LCG vs MT vs OS CSPRNG (stats + attack demos)")
    ap.add_argument("--n", type=int, default=200000, help="Tokens per RNG")
    ap.add_argument("--seed", type=int, default=1, help="Seed for fixed-seed experiments (LCG/MT)")
    ap.add_argument("--lcg_a", type=int, default=1664525)
    ap.add_argument("--lcg_c", type=int, default=1013904223)
    ap.add_argument("--out_prefix", type=str, default="salt_token", help="Prefix of saved plot filenames")

    ap.add_argument("--no_mt", action="store_true", help="Skip MT (only LCG vs CSPRNG)")
    ap.add_argument("--no_plots", action="store_true", help="Skip saving plots")
    ap.add_argument("--verbose_counts", action="store_true", help="Print full 0..15 counts for token + each word")

    # Attack demos
    ap.add_argument("--demo_time_seed", action="store_true",
                    help="Attack demo A: time-seeded seed recovery + predict token#2 (closed loop)")
    ap.add_argument("--time_window", type=int, default=30, help="Seed brute-force time window (seconds)")

    ap.add_argument("--demo_lcg_recover", action="store_true",
                    help="Attack demo B: recover LCG (a,c) from 3 outputs and predict next u32")
    ap.add_argument("--lcg_recover_tries", type=int, default=20, help="Auto-tries for LCG recovery demo")

    # Extra plots
    ap.add_argument("--plot_per_word", action="store_true",
                    help="Also save per-word lasthex plot and per-word low16 scatter plots")

    args = ap.parse_args()

    # ---- Generate tokens ----
    tokens_lcg, words_lcg = gen_tokens_lcg(args.n, seed=args.seed, a=args.lcg_a, c=args.lcg_c)
    tokens_csp, words_csp = gen_tokens_csprng(args.n)

    stats_list: List[Stats] = []
    stats_lcg = compute_stats("LCG(128 via 4x u32)", tokens_lcg, words_lcg)
    stats_list.append(stats_lcg)

    if not args.no_mt:
        tokens_mt, words_mt = gen_tokens_mt(args.n, seed=args.seed)
        stats_mt = compute_stats("MT19937(128 via 4x u32)", tokens_mt, words_mt)
        stats_list.append(stats_mt)
    else:
        tokens_mt, words_mt = None, None

    stats_csp = compute_stats("OS CSPRNG (secrets.token_bytes)", tokens_csp, words_csp)
    stats_list.append(stats_csp)

    # ---- Print stats ----
    for st in stats_list:
        print_stats(st, verbose_counts=args.verbose_counts)

    # ---- Plots ----
    if args.no_plots:
        if not HAS_MPL:
            print("matplotlib not available; plots skipped.")
    else:
        if not HAS_MPL:
            print("matplotlib not available; plots skipped. (Install matplotlib to enable plots.)")
        else:
            plot_last_hex_digit(stats_list, f"{args.out_prefix}_lasthex.png")
            plot_scatter_low16_from_tokens(tokens_lcg, "LCG: scatter of successive low16 (token)", f"{args.out_prefix}_lcg_scatter.png")
            if tokens_mt is not None:
                plot_scatter_low16_from_tokens(tokens_mt, "MT19937: scatter of successive low16 (token)", f"{args.out_prefix}_mt_scatter.png")
            plot_scatter_low16_from_tokens(tokens_csp, "OS CSPRNG: scatter of successive low16 (token)", f"{args.out_prefix}_csprng_scatter.png")

            if args.plot_per_word:
                # per-word lasthex plots
                plot_last_hex_digit_per_word(stats_lcg, f"{args.out_prefix}_lcg_word_lasthex.png")
                if tokens_mt is not None:
                    plot_last_hex_digit_per_word(stats_mt, f"{args.out_prefix}_mt_word_lasthex.png")
                plot_last_hex_digit_per_word(stats_csp, f"{args.out_prefix}_csprng_word_lasthex.png")

                # per-word low16 scatter plots (stronger structural visualization)
                plot_scatter_low16_per_word(words_lcg, "LCG", f"{args.out_prefix}_lcg")
                if words_mt is not None:
                    plot_scatter_low16_per_word(words_mt, "MT19937", f"{args.out_prefix}_mt")
                plot_scatter_low16_per_word(words_csp, "OS CSPRNG", f"{args.out_prefix}_csprng")

            print(f"Saved plots: {args.out_prefix}_*.png")

    # ---- Attack demo A: time-seeded seed recovery + predict token#2 ----
    if args.demo_time_seed:
        print("\n=== Attack demo A: time-seeded predictability (seed recovery + predict token#2) ===")
        t = int(time.time())
        approx_time = t  # attacker assumes around now (same second)
        kinds = ["lcg"] if args.no_mt else ["lcg", "mt"]

        for kind in kinds:
            victim_seed = t
            t1_hex, t2_true = two_tokens_hex_from_seed(kind, seed=victim_seed, a=args.lcg_a, c=args.lcg_c)

            rec = brute_force_time_seed_and_predict(
                kind=kind,
                observed_t1_hex=t1_hex,
                approx_time=approx_time,
                window=args.time_window,
                a=args.lcg_a,
                c=args.lcg_c
            )

            print(f"\n[{kind}] victim seed (hidden)         : {victim_seed}")
            print(f"[{kind}] observed token #1 (hex)     : {t1_hex}")
            print(f"[{kind}] victim token #2 (true, hex) : {t2_true}")

            if rec is None:
                print(f"[{kind}] attacker failed within ±{args.time_window}s window (unexpected here).")
            else:
                seed_hat, t2_pred = rec
                print(f"[{kind}] recovered seed_hat          : {seed_hat}")
                print(f"[{kind}] predicted token #2 (hex)    : {t2_pred}")
                print(f"[{kind}] prediction success          : {t2_pred == t2_true}")

        print("\nNote: This demo shows why 'time as seed' is dangerous for tokens/salts; use OS CSPRNG instead.")

    # ---- Attack demo B: LCG parameter recovery ----
    if args.demo_lcg_recover:
        demo_lcg_param_recovery(true_seed=args.seed, true_a=args.lcg_a, true_c=args.lcg_c, max_tries=args.lcg_recover_tries)


if __name__ == "__main__":
    main()
