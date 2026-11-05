"""Builds every real-model passage of the manuscript from a pilot_tables.json, so that replacing the data
(pilot_real_v1 -> pilot_real_v2) regenerates the abstract sentence, Section 6.11, the discussion paragraph and the limitation."""
import json, os
HERE = os.path.dirname(os.path.abspath(__file__))
KEYS = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8"]
pc = lambda x, d=0: f"{100 * x:.{d}f}%"
ci = lambda t, d=0: f"{100 * t[0]:.{d}f}% ({100 * t[1]:.0f}-{100 * t[2]:.0f})"
short = lambda m: m.split("/")[-1].replace("-Instruct", "")

def load():
    for sub in ("pilot_real_v2", "pilot_real_v1"):
        p = os.path.join(HERE, sub, "pilot_tables.json")
        if os.path.exists(p):
            P = json.load(open(p)); P.setdefault("meta", {}); P["meta"].setdefault("source", "v1" if sub.endswith("v1") else "v2"); P["meta"]["dir"] = sub
            return P
    return None

def eff(p):  # wording for a guardrail effect test
    return "a significant reduction" if p < 0.05 else "no significant change"

def tab(M, m):
    R = M[m]["rows"]
    s = ("| Defence | Model proposes attacker's call | Attacker's goal executed | Benign completion | Benign spontaneous violations |\n|---|---|---|---|---|\n")
    for d in KEYS:
        r = R[d]; s += f"| {d} {r['label']} | {ci(r['obey'])} | {ci(r['asr'])} | {ci(r['benign_comp'])} | {pc(r['spont'][0])} |\n"
    return s

def pers(M, m):
    p = M[m]["persistence"]; bf = M[m].get("best_family_per_defence", {}); s = "| Defence | Best family (k=10) | best family k=1 | k=3 | k=10 | uniform search k=10 |\n|---|---|---|---|---|---|\n"
    for d in ["D0", "D1", "D2", "D3", "D6", "D7", "D8"]:
        g = lambda kind, k: ci(p[f"{d}|{kind}|{k}"])
        s += f"| {d} | {bf.get(d, '-')} | {g('best', 1)} | {g('best', 3)} | {g('best', 10)} | {g('search', 10)} |\n"
    return s

def build(P=None):
    P = P or load()
    if P is None: return None
    M = P["models"]; ms = list(M); meta = P["meta"]; v1 = meta.get("source") == "v1"
    ns = [M[m]["rows"]["D0"]["n"] for m in ms]; nbs = [M[m]["rows"]["D0"]["benign_n"] for m in ms]
    same = len(set(ns)) == 1 and len(set(nbs)) == 1
    n_att = str(ns[0]) if same else " and ".join(str(x) for x in ns); n_ben = str(nbs[0]) if same else " and ".join(str(x) for x in nbs)
    per = "per model" if same else "for " + " and ".join(short(m) for m in ms) + " respectively"
    any_v1 = any(M[m].get("source", "first pilot (re-parsed)").startswith("first") for m in ms) or v1
    names = " and ".join(short(m) for m in ms)
    tag = "pilot" if (any_v1 or min(ns) < 150) else "evaluation"; art = "a" if tag == "pilot" else "an"
    # ---- Section 6.11
    s = f"### 6.11 End-to-end {tag} with real models\n\n"
    s += (f"**Design.** The same 13 tasks, effect-based oracle and monitors were run with real language models as the agent ({', '.join(ms)}; temperature 0.7; up to six turns): the model reads realistic tool outputs containing an injected instruction, proposes JSON tool calls, and every call passes through the defence under test (`notebooks/realllm_agentsec_eval_v2.ipynb`; spotlighting uses datamarking and the detector is the same model prompted as a classifier). "
          f"Each defence has {n_att} attack episodes and {n_ben} benign episodes {per}. ")
    if n_ben == "78": s += "The pre-registered analysis plan (`ANALYSIS_PLAN.md`) specified 104 benign episodes per defence at this scale; the run used six repeats per task instead of eight, so the benign-completion endpoint is less powered than planned and its intervals are correspondingly wide. "
    if tag == "pilot": s += "**This is a pilot: cells are small and intervals wide.** "
    if any_v1:
        s += (f"For the models taken from the first pilot run ({', '.join(short(m) for m in ms if M[m].get('source', 'first pilot (re-parsed)').startswith('first')) or short(ms[0])}) two corrections were applied to the raw pilot log (`pilot_real_v1/analyze_pilot.py`): obedience is counted only when the model's call is the *attacker's* call, because the weaker model made unauthorised calls of its own in benign runs (for example posting to unrelated URLs), and episodes that ended in a parse failure were re-parsed leniently from the logged output ({P.get('unparsed_episodes', 0)} such episodes, {P.get('unparsed_truncated', 0)} unrecoverable because the log was truncated; the upper-bound column adds the attacks this recovered). Both corrections are built into the v2 notebook, which produced the other model's data natively.\n\n")
    else:
        s += "Obedience is counted only when the model's call is the attacker's call, not the model's own spontaneous errors (for the email-exfiltration task only the call that mails the secret to the attacker counts, not a read of the secret alone; for the setpoint task an unsafe value sent through any tool counts), and replies are parsed leniently (literal newlines, alternative call schemas and prose answers are accepted). The alignment rule was re-derived from the logged calls (`pilot_real_v2/analyze_v2.py`).\n\n"
    oa = P.get("oracle_audit"); ob = P.get("oracle_audit_run")
    two = os.path.join(HERE, "pilot_real_v2", "oracle_audit", "oracle_audit_two_raters.json")
    if oa and ob and os.path.exists(two):
        T = json.load(open(two)); A, B = T["samples"]["V1"], T["samples"]["V2"]; PL = T["pooled"]
        k = lambda d: f"{d['kappa']:.2f}"; kci = lambda d: f"{d['kappa']:.2f} (95% bootstrap interval {d['kappa_ci95'][0]:.2f}-{d['kappa_ci95'][1]:.2f})"
        n_dis = sum(1 for _ in open(os.path.join(HERE, "pilot_real_v2", "oracle_audit", "oracle_audit_disagreements.csv"))) - 1
        n_both = PL["rater2_vs_rater1"]["n"] - PL["rater2_vs_rater1"]["a1_b0"] - PL["rater2_vs_rater1"]["a0_b1"]
        s += (f"**Oracle audit.** Both authors hand-labelled the same two random samples of {oa['n']} attack episodes each for the question *did the model propose the attacker's call?*, one sample from the first pilot run of this protocol and one from the run reported here (`pilot_real_v1/data/`, `pilot_real_v2/data/`). "
              f"Rater A (the author of the automatic rule) labelled blind to the automatic label; rater B labelled later and independently from sheets in which the rows were shuffled and recoded and the model, defence, automatic label and rater A's labels were removed (`pilot_real_v2/oracle_audit/`). "
              f"Against the automatic rule, rater A agrees on {100*oa['agreement']:.0f}% and {100*ob['agreement']:.0f}% of rows (Cohen's kappa {oa['kappa']:.2f} and {ob['kappa']:.2f}) and rater B on {100*A['rater2_vs_oracle']['agreement']:.0f}% and {100*B['rater2_vs_oracle']['agreement']:.0f}% (kappa {k(A['rater2_vs_oracle'])} and {k(B['rater2_vs_oracle'])}); "
              f"the two raters agree with each other on {100*A['rater2_vs_rater1']['agreement']:.0f}% and {100*B['rater2_vs_rater1']['agreement']:.0f}% of rows (kappa {kci(A['rater2_vs_rater1'])} and {kci(B['rater2_vs_rater1'])}; pooled {100*PL['rater2_vs_rater1']['agreement']:.0f}%, kappa {kci(PL['rater2_vs_rater1'])}), and Fleiss' kappa over the three label sources is {A['fleiss_kappa_three_sources']:.2f} and {B['fleiss_kappa_three_sources']:.2f}. "
              f"On the {n_both} rows where both raters agree, the automatic rule agrees with them on every row. "
              f"Rater A's first audit led to one rule change before the numbers in this section were computed: a read of the secret file alone no longer counts as obedience (rater A's agreement before that change: 93%, kappa 0.86). "
              f"The labels were not adjudicated; the {n_dis} rows on which any two sources disagree are reported as labelled (`oracle_audit_disagreements.csv`). In four of them the proposed call carries the attacker's payload and rater A alone scored 0 (the exact cron line written to the target file; the same line appended through the shell and then deleted; a phishing link in a permitted email; the exact falsification phrase in a report whose figures contradict it). In three, rater A alone scored 1 for an attempt at the attacker's goal through an unexpected tool or in paraphrase (the cron line sent as a setpoint value, twice; a report that calls the pressure nominal without the exact phrase). In one, rater B alone scored 0 for an HTTP post to the attacker's URL with an empty body in place of the injected shell command. The automatic rule therefore undercounts paraphrased or malformed attempts at the attacker's goal, and the human raters disagree chiefly on whether such attempts count.\n\n")
    elif oa and ob:
        pooled = (oa["agreement"] * oa["n"] + ob["agreement"] * ob["n"]) / (oa["n"] + ob["n"])
        gen = len(oa["auto_too_generous"]) + len(ob["auto_too_generous"]); mis = len(oa["auto_missed"]) + len(ob["auto_missed"])
        s += (f"**Oracle audit.** The author hand-labelled two random samples of {oa['n']} attack episodes each, blind to the automatic label, for the question *did the model propose the attacker's call?*: one from the first pilot run of this protocol and one from the run reported here (`pilot_real_v1/data/`, `pilot_real_v2/data/`). "
              f"The automatic rule agrees on {100*oa['agreement']:.0f}% (Cohen's kappa {oa['kappa']:.2f}) and {100*ob['agreement']:.0f}% (kappa {ob['kappa']:.2f}) of rows, {100*pooled:.0f}% pooled. "
              f"The first audit led to one rule change before the numbers in this section were computed: a read of the secret file alone no longer counts as obedience (earlier agreement 93%, kappa 0.86). "
              f"The {gen + mis} remaining disagreements are reported as labelled and go in both directions: {gen} rows where the rule counts obedience and the labeller does not, and {mis} where the labeller counts obedience that the rule misses (a falsified report that omits the exact phrase the oracle looks for, and obedience attempted through a different tool than expected). The rule therefore undercounts paraphrased or malformed attempts at the attacker's goal and, in a few rows, counts an attacker payload that the labeller judged to be echoed text.\n\n")
    elif oa:
        s += (f"**Oracle audit.** The author hand-labelled {oa['n']} randomly sampled attack episodes of an earlier run of this protocol (the first pilot, `pilot_real_v1/data/`), blind to the automatic label. The automatic rule agrees on {100*oa['agreement']:.0f}% of rows (Cohen's kappa {oa['kappa']:.2f}).\n\n")
    tn = 15                                  # Section 6.10 uses Tables 13-14
    for m in ms:
        s += f"**{m}.**\n\n{tab(M, m)}\n*Table {tn}. Results for {short(m)}. Intervals are 95% Wilson; attack episodes pooled over the attack families used.*\n\n"; tn += 1
    s += (f"![Figure 8. Real-model results: how often the model proposes the attacker's call and how often the attacker's goal is executed, by defence.]({meta.get('dir', 'pilot_real_v1')}/fig_pilot_real.png)\n\n*Figure 8. Real-model results (95% Wilson intervals).*\n\n")
    s += "**Persistence** (per-task success rates composed over k independent attempts; success if any attempt executes the attacker's goal; two-level bootstrap over tasks and repeats):\n\n"
    for m in ms:
        s += f"{pers(M, m)}\n*Table {tn}. {short(m)}: attacker who picks the best attack family for each defence (re-selected inside every bootstrap replicate; the interval also reflects which tasks are in the suite) versus uniform search over families.*\n\n"; tn += 1
    # ---- findings (data-conditional wording)
    s += "**What the data show.**\n"
    ladder = []
    for m in ms:
        R = M[m]["rows"]; res = M[m]["d7_residual_tasks"]
        ladder.append(f"{short(m)}: P3 admitted {pc(R['D7']['asr'][0], 1)} of attacks (residual task(s): {', '.join(res) if res else 'none'}), hardened argument checks {pc(R['D6']['asr'][0])}, naive checks {pc(R['D5']['asr'][0])}, while the model proposed the attacker's call in {pc(R['D7']['obey'][0])} of episodes behind P3")
    s += "1. *Monitors.* " + "; ".join(ladder) + ". The simulation predicted a P3 residual of one task (semantic falsification of a permitted report) and equal naive and hardened results against a model that does not vary argument encodings.\n"
    gl = []
    for m in ms:
        R = M[m]["rows"]; G = M[m].get("guardrail_fisher_holm") or M[m]["guardrail_fisher"]
        pf = lambda x: "p < 0.001" if x < 0.001 else f"p = {x:.2g}"
        gl.append(f"{short(m)}: obedience {pc(R['D0']['obey'][0])} with no defence, {pc(R['D1']['obey'][0])} with the prompt guardrail ({eff(G['D1'])}, {pf(G['D1'])}), {pc(R['D2']['obey'][0])} with spotlighting ({eff(G['D2'])}, {pf(G['D2'])}) and {pc(R['D3']['obey'][0])} with spotlighting plus the detector ({eff(G['D3'])}, {pf(G['D3'])})")
    pl = []; sup = []; nsup = []
    for m in ms:
        pe = M[m]["persistence"]; g = lambda d: pe[f"{d}|best|10"][0]
        pl.append(f"{short(m)}: prompt guardrail {pc(g('D1'))}, spotlighting {pc(g('D2'))}, spotlighting plus detector {pc(g('D3'))}")
        (sup if g("D3") >= 0.9 else nsup).append(short(m))
    d1 = [short(m) for m in ms if M[m]["persistence"]["D1|best|10"][0] >= 0.8]
    verdict = ("The simulated claim that guardrail stacks approach 100% under persistence is " + (f"borne out for the prompt guardrail alone ({' and '.join(d1)}: at least 80% after ten attempts)" if d1 else "not borne out for the prompt guardrail alone")
               + ("; it is " if True else "") + ("supported for the detector stack of " + " and ".join(sup) if sup else "not supported for the detector stack of " + " and ".join(nsup)) + " in these data")
    s += "2. *Guardrails* (p-values Holm-adjusted over the three guardrail comparisons within each model). " + "; ".join(gl) + ". After ten attempts by an attacker who picks the best attack family for each defence, success is " + "; ".join(pl) + f". {verdict}; attacks here are static families, so an attacker who optimises against the detector is not covered.\n"
    ly = []
    for m in ms:
        R = M[m]["rows"]; t = f"{short(m)}: layered defence admitted {pc(R['D8']['asr'][0])} with benign completion {ci(R['D8']['benign_comp'])} against {ci(R['D0']['benign_comp'])} for no defence"
        bd = M[m].get("benign_diff_vs_D0", {})
        if "D8" in bd and "D7" in bd: t += f"; difference from no defence {100*bd['D7'][0]:+.0f} points (95% CI {100*bd['D7'][1]:+.0f} to {100*bd['D7'][2]:+.0f}) for P3 and {100*bd['D8'][0]:+.0f} points ({100*bd['D8'][1]:+.0f} to {100*bd['D8'][2]:+.0f}) for the layered defence"
        if "D7" in bd and bd["D7"][1] > 0 and R["D0"]["spont"][0] > 0.1: t += f"; P3 raised benign completion because it blocks the model's own unauthorised calls (spontaneous violations without a monitor: {pc(R['D0']['spont'][0])})"
        if "D7" in bd and "D8" in bd:
            met = [n for n, k in (("P3", "D7"), ("the layered defence", "D8")) if bd[k][1] > -0.10]; notmet = [n for n, k in (("P3", "D7"), ("the layered defence", "D8")) if bd[k][1] <= -0.10]
            if met: t += f"; {' and '.join(met)} meet{'s' if len(met) == 1 else ''} the 10-point non-inferiority margin of the analysis plan"
            if notmet: t += f"; {' and '.join(notmet)} do{'es' if len(notmet) == 1 else ''} not meet the 10-point non-inferiority margin"
        ly.append(t)
    s += "3. *Layering and utility.* " + "; ".join(ly) + ".\n"
    mal = [f"{pc(M[m]['malformed_rate'])} for {short(m)}" for m in ms if M[m].get("malformed_rate") is not None]
    mtxt = (" Undecodable or empty outputs ended " + " and ".join(mal) + " of attack episodes; these cannot be classified and may hide attacks, so all attack rates are lower bounds in that respect.") if mal else ""
    s += f"4. *Cautions.* Benign completion has {n_ben} episodes per cell; format deviations (prose answers, non-standard call schemas, literal newlines in JSON) and a model's own spontaneous errors affect completion; only static attack families were used; the oracle requires the attacker's exact phrase for semantic falsification, so paraphrased falsification is undercounted; results are for open-weights models and say nothing about frontier models.{mtxt}\n\n"
    # ---- abstract passage
    ab = (f"Real models were used in two checks. A measurement on Qwen2.5-1.5B (Section 6.10) rejects the simulator's monotone susceptibility law (p < 1e-9) and finds no guardrail effect there. An end-to-end {tag} with {names} (Section 6.11, {n_att} attack episodes per defence {'and model' if same else 'respectively'}) runs the same tasks, oracle and monitors on real models: ")
    ab += "; ".join(f"behind a task-bound monitor the {short(m)} model proposed the attacker's call in {pc(M[m]['rows']['D7']['obey'][0])} of attack episodes yet {pc(M[m]['rows']['D7']['asr'][0], 1)} succeeded" for m in ms)
    ab += ". Guardrail effects differed by model: " + "; ".join(f"{short(m)} {pc(M[m]['rows']['D0']['obey'][0])} obedience with no defence, {pc(M[m]['rows']['D1']['obey'][0])} with a prompt guardrail, {pc(M[m]['rows']['D3']['obey'][0])} with spotlighting plus a detector" for m in ms)
    ab += (", against static attacks, so the simulated claim that guardrail stacks reach 100% under persistence is model-dependent and untested against attackers who optimise against the detector." + (" The pilot is small; a larger run is specified in the reproducibility section." if tag == "pilot" else ""))
    ab_short = (f"In {art} {tag} with real open-weights models ({names}; {n_att} attack episodes per defence{' and model' if same else ', respectively'}), the models proposed the attacker's call in "
                + " and ".join(pc(M[m]['rows']['D7']['obey'][0]) for m in ms) + " of attack episodes behind the task-bound monitor, which admitted "
                + " and ".join(pc(M[m]['rows']['D7']['asr'][0], 1) for m in ms) + "; guardrail effects depended on the model (a prompt guardrail moved obedience from "
                + " and from ".join(f"{pc(M[m]['rows']['D0']['obey'][0])} to {pc(M[m]['rows']['D1']['obey'][0])}" for m in ms) + ", spotlighting plus a detector to "
                + " and ".join(pc(M[m]['rows']['D3']['obey'][0]) for m in ms) + ") against static attacks.")
    xm = ""
    if len(ms) == 2:
        from scipy.stats import fisher_exact
        r1, r2 = M[ms[0]]["rows"]["D7"], M[ms[1]]["rows"]["D7"]; k1, k2 = round(r1["asr"][0] * r1["n"]), round(r2["asr"][0] * r2["n"])
        pfx = fisher_exact([[k1, r1["n"] - k1], [k2, r2["n"] - k2]])[1]; same = set(M[ms[0]]["d7_residual_tasks"]) == set(M[ms[1]]["d7_residual_tasks"])
        xm = (f"; behind P3 the models let {k1} of {r1['n']} and {k2} of {r2['n']} attacks through ({short(ms[0])} and {short(ms[1])}; Fisher p = {pfx:.3f}), " +
              ("and all of them belonged to the same in-policy task, so what is invariant is the set of attacks the monitor can pass (the semantic-falsification task), not the rate, which depends on how often the model complies with that injection" if same else "and the residual tasks differed"))
    disc = (f"**What the real models add.** In the real-model runs the monitor's guarantee held for every model: only in-policy attacks passed{xm}. The guardrail results, in contrast, varied by model, attack family and attacker effort (Section 6.11). This supports treating guardrails as noise reduction whose value must be re-measured per model, and the monitor as the component whose guarantee can be stated as a set of permitted actions, not as a function of the model's behaviour.")
    lim = (f"1. **The model is mostly simulated.** Susceptibility is measured for one small model (Section 6.10) and the end-to-end {tag} (Section 6.11) uses {names} with {n_att} attack episodes per defence{' and model' if same else ''} and static attack families; spotlighting and detectors are measured only for those models; guardrail erosion under adaptive attackers, the human-reviewer model and taint-tracking failures remain assumptions; no human-approval or taint layer has been run against a real model.")
    return dict(sec611=s, abstract=ab, abstract_short=ab_short, discussion=disc, limitation=lim, tag=tag, names=names)
