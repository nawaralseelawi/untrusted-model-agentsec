#!/usr/bin/env python3
"""Score the second rater's blind labels against the automatic oracle and the first rater.

Inputs:
  study_dir   path to agentsec_study (provides label_audit.py, the samples and the first rater's labels)
  key_csv     KEY_do_not_open_before_labelling.csv written by build_blind_sheets.py
  sheet_v1    filled oracle_blind_sheet_V1_Nawar.xlsx
  sheet_v2    filled oracle_blind_sheet_V2_Nawar.xlsx

Usage:
  python -I score_second_rater.py <study_dir> <key_csv> <sheet_v1> <sheet_v2> [--out results_dir]
  python -I score_second_rater.py <study_dir> <key_csv> --self-test
      (uses the first rater's labels as if they were the second rater's; the oracle-vs-rater
       figures must then equal the manuscript's 97% / kappa 0.94 and 96% / kappa 0.92)

Reported per sample and pooled: percent agreement and Cohen's kappa (with a percentile
bootstrap 95% interval, 5000 resamples, fixed seed) for rater 2 vs oracle, rater 2 vs
rater 1 and rater 1 vs oracle; Fleiss' kappa over the three label sources; the oracle
against the two-rater consensus on the rows where both raters agree; and every
disagreement listed by sheet code and original row_id.
"""
import argparse
import csv
import importlib.util
import json
import os
import random
import sys

BOOT = 5000
SEED = 20261103
SOURCES = {
    "V1": ("pilot_real_v1/data/label_sample.csv", "pilot_real_v1/data/human_labels_pilot.csv"),
    "V2": ("pilot_real_v2/data/label_sample_v2run.csv", "pilot_real_v2/data/human_labels_v2run.csv"),
}


def load_label_audit(study_dir):
    spec = importlib.util.spec_from_file_location(
        "label_audit", os.path.join(study_dir, "pilot_real_v2", "label_audit.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    sys.path.insert(0, study_dir)
    import agentsec_sim as sim
    return mod, {t.name: t.id for t in sim.TASKS}


def cohen_kappa(a, b):
    n = len(a)
    if n == 0:
        return float("nan")
    po = sum(x == y for x, y in zip(a, b)) / n
    pa, pb = sum(a) / n, sum(b) / n
    pe = pa * pb + (1 - pa) * (1 - pb)
    return (po - pe) / (1 - pe) if pe < 1 else float("nan")


def fleiss_kappa(columns):
    """columns: list of equally long 0/1 label lists (one per source)."""
    m, n = len(columns), len(columns[0])
    ones = [sum(col[i] for col in columns) for i in range(n)]
    p_i = [(k * (k - 1) + (m - k) * (m - k - 1)) / (m * (m - 1)) for k in ones]
    p_bar = sum(p_i) / n
    p1 = sum(ones) / (n * m)
    pe = p1 ** 2 + (1 - p1) ** 2
    return (p_bar - pe) / (1 - pe) if pe < 1 else float("nan")


def boot_ci(a, b, rng):
    n = len(a)
    vals = []
    for _ in range(BOOT):
        idx = [rng.randrange(n) for _ in range(n)]
        k = cohen_kappa([a[i] for i in idx], [b[i] for i in idx])
        if k == k:
            vals.append(k)
    vals.sort()
    if not vals:
        return [float("nan"), float("nan")]
    return [vals[int(0.025 * len(vals))], vals[min(len(vals) - 1, int(0.975 * len(vals)))]]


def pair_stats(a, b, rng):
    n = len(a)
    agree = sum(x == y for x, y in zip(a, b))
    return {"n": n, "agreement": agree / n, "kappa": cohen_kappa(a, b), "kappa_ci95": boot_ci(a, b, rng),
            "a1_b0": sum(1 for x, y in zip(a, b) if x and not y),
            "a0_b1": sum(1 for x, y in zip(a, b) if not x and y)}


def read_sheet(path):
    from openpyxl import load_workbook
    ws = load_workbook(path, data_only=True)["Label"]
    out, notes, blanks = {}, {}, []
    for r in ws.iter_rows(min_row=2, values_only=True):
        if r[0] is None:
            continue
        v = str(r[6]).strip() if r[6] is not None else ""
        if v in ("0", "1", "0.0", "1.0"):
            out[r[0]] = int(float(v))
            notes[r[0]] = r[7] or ""
        else:
            blanks.append(r[0])
    return out, notes, blanks


def load_rater1(path):
    return {int(r["row_id"]): int(r["human_label_obeyed_attacker"])
            for r in csv.DictReader(open(path, encoding="utf-8"))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("study_dir")
    ap.add_argument("key_csv")
    ap.add_argument("sheets", nargs="*")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--out", default="oracle_audit_results")
    args = ap.parse_args()

    study = os.path.abspath(args.study_dir)
    la, name2id = load_label_audit(study)
    key = list(csv.DictReader(open(args.key_csv, encoding="utf-8")))
    code2row = {k["code"]: int(k["row_id"]) for k in key}
    rng = random.Random(SEED)
    report = {"self_test": args.self_test, "samples": {}}
    pooled = {"r2": [], "r1": [], "oracle": []}
    disagreements = []

    for idx, prefix in enumerate(("V1", "V2")):
        sample_rel, r1_rel = SOURCES[prefix]
        sample = list(csv.DictReader(open(os.path.join(study, sample_rel), encoding="utf-8")))
        oracle = {i: int(la.auto_label(r, name2id)) for i, r in enumerate(sample)}
        rater1 = load_rater1(os.path.join(study, r1_rel))
        if args.self_test:
            r2_by_code = {c: rater1[r] for c, r in code2row.items() if c.startswith(prefix)}
            notes, blanks = {}, []
        else:
            r2_by_code, notes, blanks = read_sheet(args.sheets[idx])
        if blanks:
            print(f"{prefix}: {len(blanks)} rows without a 0/1 label: {blanks[:10]}{' ...' if len(blanks) > 10 else ''}")
        rows = sorted(code2row[c] for c in r2_by_code)
        row2code = {code2row[c]: c for c in r2_by_code}
        r2 = [r2_by_code[row2code[i]] for i in rows]
        r1 = [rater1[i] for i in rows]
        orc = [oracle[i] for i in rows]
        both = [i for i, (x, y) in enumerate(zip(r1, r2)) if x == y]
        report["samples"][prefix] = {
            "rows_labelled": len(rows),
            "rows_missing": len(blanks),
            "rater2_vs_oracle": pair_stats(r2, orc, rng),
            "rater2_vs_rater1": pair_stats(r2, r1, rng),
            "rater1_vs_oracle": pair_stats(r1, orc, rng),
            "fleiss_kappa_three_sources": fleiss_kappa([r1, r2, orc]),
            "oracle_vs_consensus": pair_stats([r1[i] for i in both], [orc[i] for i in both], rng) if both else None,
            "prevalence": {"oracle": sum(orc) / len(orc), "rater1": sum(r1) / len(r1), "rater2": sum(r2) / len(r2)},
        }
        for i, row_id in enumerate(rows):
            if len({r1[i], r2[i], orc[i]}) > 1:
                s = sample[row_id]
                disagreements.append({"sample": prefix, "code": row2code[row_id], "row_id": row_id,
                                      "task": s["task_name"], "defence": s["defence"], "model": s["model"],
                                      "oracle": orc[i], "rater1": r1[i], "rater2": r2[i],
                                      "rater2_note": notes.get(row2code[row_id], "")})
        pooled["r2"] += r2
        pooled["r1"] += r1
        pooled["oracle"] += orc

    report["pooled"] = {
        "rater2_vs_oracle": pair_stats(pooled["r2"], pooled["oracle"], rng),
        "rater2_vs_rater1": pair_stats(pooled["r2"], pooled["r1"], rng),
        "rater1_vs_oracle": pair_stats(pooled["r1"], pooled["oracle"], rng),
        "fleiss_kappa_three_sources": fleiss_kappa([pooled["r1"], pooled["r2"], pooled["oracle"]]),
    }
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "oracle_audit_two_raters.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1)
    with open(os.path.join(args.out, "oracle_audit_disagreements.csv"), "w", newline="", encoding="utf-8") as f:
        fields = ["sample", "code", "row_id", "task", "defence", "model", "oracle", "rater1", "rater2", "rater2_note"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(disagreements)

    def line(name, s):
        lo, hi = s["kappa_ci95"]
        return f"  {name:<20} n={s['n']:<4} agreement {s['agreement']:.0%}  kappa {s['kappa']:.2f} [{lo:.2f}, {hi:.2f}]"

    for prefix in ("V1", "V2"):
        s = report["samples"][prefix]
        print(f"{prefix}:")
        print(line("rater 2 vs oracle", s["rater2_vs_oracle"]))
        print(line("rater 2 vs rater 1", s["rater2_vs_rater1"]))
        print(line("rater 1 vs oracle", s["rater1_vs_oracle"]))
        print(f"  Fleiss kappa (3 sources) {s['fleiss_kappa_three_sources']:.2f}")
    p = report["pooled"]
    print("pooled:")
    print(line("rater 2 vs oracle", p["rater2_vs_oracle"]))
    print(line("rater 2 vs rater 1", p["rater2_vs_rater1"]))
    print(line("rater 1 vs oracle", p["rater1_vs_oracle"]))
    print(f"rows with any disagreement: {len(disagreements)} -> {args.out}/oracle_audit_disagreements.csv")


if __name__ == "__main__":
    main()
