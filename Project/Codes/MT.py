import numpy as np
from collections import deque
import random
import matplotlib.pyplot as plt

# ============================================================
# Config
# ============================================================
N = 1_000_000              # state space: 0..999999
PROGRESS_STEP = 100_000    # progress printing
SCATTER_SAMPLE = 200_000   # points for x-f scatter
SCATTER_NORMALIZE = True   # plot x/N, f(x)/N if True

OUT_SCATTER = "MT-Scatter-x-f.png"
OUT_DIGIT = "MT-Digit.png"


# ============================================================
# 1) Build MT-derived mapping f(x) and OVERALL digit stats (one figure)
#    f(x) = MT(seed=x).randrange(N)
# ============================================================
def build_mt_mapping_and_digit_overall(N: int, progress_step: int = 100_000):
    """
    Returns:
      nxt: np.ndarray (N,), nxt[x] = f(x)
      digit_overall: counts[10] over all 6 decimal digits pooled (sum = 6N)
    """
    nxt = np.empty(N, dtype=np.int32)
    digit_overall = np.zeros(10, dtype=np.int64)

    rng = random.Random()  # MT19937, reused for speed

    for x in range(N):
        rng.seed(x)
        y = rng.randrange(N)
        nxt[x] = y

        # overall digit stats over 6 decimal digits (with leading zeros)
        t = y
        for _ in range(6):
            digit_overall[t % 10] += 1
            t //= 10

        if (x + 1) % progress_step == 0:
            print(f"build f(x): {x+1}/{N}")

    return nxt, digit_overall


# ============================================================
# 2) Functional graph stats: period / preperiod (O(N))
# ============================================================
def analyze_functional_graph(nxt: np.ndarray):
    """
    Functional graph with outdegree=1 for each node.
    Returns:
      period[i]    = cycle length of component containing i
      preperiod[i] = distance from i to cycle (tail length)
      summary      = dict of key stats
    """
    N = int(nxt.shape[0])
    nxt64 = nxt.astype(np.int64, copy=False)

    indeg = np.bincount(nxt64, minlength=N).astype(np.int32)

    # peel nodes not in cycles
    q = deque(np.flatnonzero(indeg == 0).tolist())
    order = np.empty(N, dtype=np.int32)
    t = 0
    while q:
        v = q.popleft()
        order[t] = v
        t += 1
        u = int(nxt64[v])
        indeg[u] -= 1
        if indeg[u] == 0:
            q.append(u)

    in_cycle = indeg > 0
    cycle_nodes = np.flatnonzero(in_cycle)

    period = np.zeros(N, dtype=np.int32)
    preperiod = np.zeros(N, dtype=np.int32)

    visited = np.zeros(N, dtype=np.bool_)
    cycle_len_hist = {}
    num_cycles = 0

    # enumerate cycles
    for v in cycle_nodes:
        if visited[v]:
            continue
        cur = int(v)
        nodes = []
        while True:
            visited[cur] = True
            nodes.append(cur)
            cur = int(nxt64[cur])
            if cur == int(v):
                break
        L = len(nodes)
        num_cycles += 1
        cycle_len_hist[L] = cycle_len_hist.get(L, 0) + 1
        for u in nodes:
            period[u] = L

    # reverse DP for tails
    for i in range(t - 1, -1, -1):
        v = int(order[i])
        u = int(nxt64[v])
        period[v] = period[u]
        preperiod[v] = preperiod[u] + 1

    summary = {
        "N": N,
        "num_cycles": int(num_cycles),
        "nodes_on_cycles": int(in_cycle.sum()),
        "nodes_off_cycles": int(N - in_cycle.sum()),
        "E_period": float(period.mean()),
        "E_preperiod": float(preperiod.mean()),
        "max_period": int(period.max()),
        "max_preperiod": int(preperiod.max()),
        "num_fixed_points": int(cycle_len_hist.get(1, 0)),
        "num_2cycles": int(cycle_len_hist.get(2, 0)),
        "cycle_len_hist": cycle_len_hist,
    }
    return period, preperiod, summary


# ============================================================
# 3) x-f scatter plot (same "x vs f(x)" style)
# ============================================================
def plot_scatter_x_fx(nxt: np.ndarray,
                      sample: int = 200_000,
                      normalize: bool = True,
                      seed: int = 1,
                      out_png: str = "MT-Scatter-x-f.png"):
    N = int(nxt.shape[0])
    rng = np.random.default_rng(seed)
    idx = rng.choice(N, size=min(sample, N), replace=False)

    xs = idx.astype(np.float64)
    ys = nxt[idx].astype(np.float64)

    if normalize:
        xs /= N
        ys /= N
        xlabel, ylabel = r"$x/N$", r"$f(x)/N$"
    else:
        xlabel, ylabel = r"$x$", r"$f(x)$"

    plt.figure()
    plt.scatter(xs, ys, s=1)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(f"MT-derived scatter: (x, f(x)), sample={len(idx)}")
    plt.tight_layout()
    plt.savefig(out_png, dpi=200)
    plt.close()
    print("saved:", out_png)


# ============================================================
# 4) Digit plot (ONE figure): overall digit frequency
# ============================================================
def plot_digit_overall(digit_overall: np.ndarray, out_png: str = "MT-Digit.png"):
    x = np.arange(10)
    plt.figure()
    plt.bar(x, digit_overall)
    plt.xticks(x)
    plt.xlabel("digit")
    plt.ylabel("count")
    plt.title("MT-derived: digit frequency (overall, 6 digits pooled)")
    plt.tight_layout()
    plt.savefig(out_png, dpi=200)
    plt.close()
    print("saved:", out_png)


# ============================================================
# 5) Main
# ============================================================
def main():
    print(f"N={N}")
    print("Step 1/3: build f(x)=MT(seed=x).randrange(N) and digit(overall) ...")
    nxt, digit_overall = build_mt_mapping_and_digit_overall(N, PROGRESS_STEP)

    print("\nStep 2/3: analyze functional graph (period / preperiod) ...")
    period, preperiod, st = analyze_functional_graph(nxt)

    print("\n=== MT-derived functional graph summary ===")
    for k in [
        "N", "num_cycles", "nodes_on_cycles", "nodes_off_cycles",
        "E_period", "E_preperiod", "max_period", "max_preperiod",
        "num_fixed_points", "num_2cycles",
    ]:
        print(f"{k:18s} = {st[k]}")

    top = sorted(st["cycle_len_hist"].items(), key=lambda kv: (-kv[1], kv[0]))[:15]
    print("\nTop cycle lengths (len -> #cycles):")
    for L, cnt in top:
        print(f"  {L:6d} -> {cnt}")

    print("\n=== Digit frequency (overall) ===")
    total = int(digit_overall.sum())  # should be 6*N
    expected = total / 10.0
    for d in range(10):
        print(f"digit {d}: {digit_overall[d]} (diff {digit_overall[d] - expected:.1f})")

    print("\nStep 3/3: plots ...")
    plot_scatter_x_fx(nxt, sample=SCATTER_SAMPLE, normalize=SCATTER_NORMALIZE, out_png=OUT_SCATTER)
    plot_digit_overall(digit_overall, out_png=OUT_DIGIT)

    print("\nDone.")

if __name__ == "__main__":
    main()
