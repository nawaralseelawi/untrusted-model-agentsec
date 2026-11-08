import json, pandas as pd
D = "results_combined"
C1 = pd.read_csv(f"{D}/C1_main.csv").set_index("key"); C2 = pd.read_csv(f"{D}/C2_thresholds.csv"); C3 = pd.read_csv(f"{D}/C3_taint_coverage.csv")
C4 = pd.read_csv(f"{D}/C4_policy_coverage.csv"); C5 = pd.read_csv(f"{D}/C5_fatigue.csv"); C6 = pd.read_csv(f"{D}/C6_susceptibility.csv"); C7 = pd.read_csv(f"{D}/C7_approval_budget.csv")
E = json.load(open("results.json")); byp = [b for b in E["E6"]["bypass"] if b["violation"]]; nv = len(byp)
adm = {m: sum(b[m] for b in byp) for m in ("P1", "P2n", "P2h", "P3")}
p = lambda x, d=1: f"{100*x:.{d}f}%"; f2 = lambda x: f"{x:.2f}"
def tbl(df, cols, heads, fmts):
    out = "| " + " | ".join(heads) + " |\n|" + "---|" * len(heads) + "\n"
    for _, r in df.iterrows(): out += "| " + " | ".join(f(r[c]) if callable(f) else str(r[c]) for c, f in zip(cols, fmts)) + " |\n"
    return out
lab = {"D0": "No defence", "D1": "In-prompt guardrail", "D2": "Guardrail + spotlighting", "D3": "Spotlight + LLM detector", "D4": "P1 tool allow-list", "D5": "P2n naive argument checks",
       "D6": "P2h hardened argument checks", "D7": "P3 task-bound capabilities + IFC", "D8": "P3 + spotlight + detector", "H1": "P3 + human (sev>=8)",
       "H2": "P3 + human + taint (sev>=3 if tainted)", "H3": "P2h + human + taint", "H4": "P1 + human + taint", "H5": "Human + taint only (no monitor)"}
t1 = "| Defence | Benign compl. | Esc. / task | A2 ASR@1 | A3 ASR@25 | A3 harm | A4 ASR | A4 severe | A4 harm |\n|---|---|---|---|---|---|---|---|---|\n"
for k, r in C1.iterrows():
    t1 += f"| {k} {lab[k]} | {p(r.completion,0)} | {r.esc:.2f} | {p(r.A2_asr,0)} | {p(r.A3_asr,0)} | {r.A3_harm:.2f} | {p(r.A4_asr,0)} | {p(r.A4_sev,0)} | {r.A4_harm:.2f} |\n"
def piv(df, idx, col, val, fmt=f2):
    P = df.pivot(index=idx, columns=col, values=val); s = "| " + idx + " | " + " | ".join(str(c) for c in P.columns) + " |\n|" + "---|" * (len(P.columns) + 1) + "\n"
    for i, r in P.iterrows(): s += f"| {i} | " + " | ".join(fmt(v) for v in r) + " |\n"
    return s
t_thr_h = piv(C2, "human_thr", "taint_thr", "A4_harm"); t_thr_e = piv(C2, "human_thr", "taint_thr", "esc")
t_cov = piv(C3[C3.taint_cov.isin([1.0, .9, .8, .6, .4, 0.0])], "taint_cov", "config", "A4_harm"); t_covs = piv(C3[C3.taint_cov.isin([1.0, .9, .8, .6, .4, 0.0])], "taint_cov", "config", "A4_sev", lambda v: p(v))
t_pol = piv(C4, "policy_cov", "config", "A4_harm"); t_pol3 = piv(C4, "policy_cov", "config", "A3_harm")
t_fat = piv(C5[C5.config == "H2"], "fatigue", "spam_decay", "A4_harm"); t_fat5 = piv(C5[C5.config == "H5"], "fatigue", "spam_decay", "A4_sev", lambda v: p(v))
C7["cap_n"] = C7.esc_cap.replace("none", 99).astype(int); c7 = C7.sort_values(["config", "cap_n"])
t7 = "| Config | Approval budget | Benign completion | A4 severe | A4 harm | A3 harm |\n|---|---|---|---|---|---|\n" + "".join(f"| {r.config} | {r.esc_cap} | {p(r.completion)} | {p(r.A4_sev)} | {r.A4_harm:.2f} | {r.A3_harm:.2f} |\n" for r in c7.itertuples())
t6 = piv(C6, "a0", "config", "A2_asr", lambda v: p(v))
g = lambda k, c: C1.loc[k, c]
import numpy as np
E5 = json.load(open("results.json"))["E5"]
_pct = lambda d, lo, hi: (float(np.percentile(E5["A3@5"][d], lo)), float(np.percentile(E5["A3@5"][d], hi)))
_c2 = C2[C2.taint_thr == 3].set_index("human_thr"); _w8, _w10 = _c2.loc[8], _c2.loc[10]
_c7 = C7.set_index(["config", "esc_cap"]); _cost = lambda cfg, cap: 100 * (_c7.loc[(cfg, "none"), "completion"] - _c7.loc[(cfg, cap), "completion"])
_esc = C1.esc[C1.esc > 0]
import os, pilot_section as PS
from refs import Cite
_cite = Cite(); c = _cite.cite
if os.environ.get("CITE_MODE") == "latex":                      # make_latex.py: keep citation keys for \cite{}, numbering comes from BibTeX unsrt
    def c(*keys):
        for k in keys: _cite.num(k)
        return "@@CITE:" + ",".join(keys) + "@@"
PIL = PS.build()

md = f"""# Treating the Model as an Untrusted Component: Deterministic Policy Enforcement, Human Approval and Taint Tracking Against Prompt Injection in Tool-Using Agents, with Validation on Open-Weights Models

**Mustafa S. Aljumaily**<sup>1,\\*</sup>, **Nawar S. Alseelawi**<sup>2</sup> and **Raghad Alshabandar**<sup>3</sup>

<sup>1</sup> ICT Department, Missan Oil Company, Missan, Iraq (mustafasadiq0@gmail.com; ORCID 0000-0002-7886-9537)  
<sup>2</sup> University of Misan, Maysan, Iraq (nawar.alseelawi@uomisan.edu.iq; ORCID 0000-0001-5739-2349)  
<sup>3</sup> National Center for Artificial Intelligence, Baghdad, Iraq (raghadalshabandar@outlook.com; ORCID 0000-0002-1393-3761)  
\\* Corresponding author: mustafasadiq0@gmail.com

---

## Abstract

Tool-using LLM agents act on instructions embedded in the data they read, so prompt injection is a structural rather than a prompt-wording problem. We compare in-prompt defences (hardened prompts, spotlighting, LLM detectors) with deterministic enforcement outside the model (four reference monitors of increasing strength), human approval and taint tracking, judged by one effect-based oracle independent of every defence in an executable environment of 13 tasks and 12 tools, with argument-fuzzing attackers and severity-weighted harm. {PIL['abstract_short']} Simulation with an assumed model covers what no real run did: under the assumed erosion law a persistent adaptive attacker or a compromised model drives every guardrail stack to {p(g('D1','A3_asr'))} attack success, whereas the task-bound monitor holds severe actions at {p(g('D7','A4_sev'))}; its residual (harm {g('D7','A4_harm'):.2f}/10) falls by {p(1-g('H2','A4_harm')/g('D7','A4_harm'),0)} under taint-triggered human review, and a human layer without a deterministic monitor fails against approval spamming unless each episode has a deterministic approval budget. Implementation quality matters: a naive monitor admits {adm['P2n']} of {nv} effective attack variants, a hardened one {adm['P2h']} and a capability-bound one {adm['P3']}. The real-model evidence is limited to two open-weights models and static attacks, the human-approval and taint results are simulation-only, and the larger model's detector stack contradicts the assumed erosion law. Code, data, a two-rater oracle audit and a notebook for repeating the real-model evaluation are provided.

**Keywords:** prompt injection, LLM agents, reference monitor, capability security, taint tracking, human-in-the-loop, adaptive attacks, zero trust, simulation.

---

## 1. Introduction

An agent that reads email, browses pages and queries databases, and then sends messages, edits configuration or sets an actuator value, mixes instructions and data in one channel {c('greshake','zverev')}. The prevailing mitigation makes the model better at ignoring injected text; its security argument is probabilistic and assumes a non-adaptive attacker {c('nasr','zhan25')}. The alternative is classical: treat the model as an untrusted, non-deterministic component and let a small deterministic mechanism authorise every proposed action {c('anderson','saltzer')}. A pragmatic third option keeps a human in the loop for high-impact actions, but humans fatigue and can be spammed {c('alahmadi')}. The question matters most in industrial and critical-infrastructure deployments, where an agent may hold tools that change configuration or actuator setpoints and a single unauthorised action can have physical consequences {c('nist80082')}. This paper compares the three approaches under one effect-based oracle and one attacker model, and asks which guarantees survive a persistent, adaptive or fully compromised model. Sections 3-5 define the threat model, the defences and the methodology; Section 6 reports simulation and real-model results; Sections 7-9 discuss implications, limits and availability.

**Contributions.** (1) A reproducible executable harness with an effect-based oracle and a ladder of four monitors implemented naively and hardened. (2) A severity-weighted harm metric, showing that binary attack-success rate hides which actions an attacker obtains. (3) A human-approval and taint-tracking layer with reviewer fatigue, approval spamming and a deterministic approval budget. (4) Failure analyses of the taint tracker and of policy completeness, each crossed with the layering. (5) A measurement and calibration pipeline that tests the susceptibility law on a real open-weights model (the assumed monotone law is rejected). (6) A consistency check against a separately built abstract model (Section 6.9; the two share design assumptions, so this is not independent evidence). (7) An end-to-end evaluation with real open-weights models running the same tasks, oracle and monitors (Section 6.11), and a notebook to repeat it at scale.

**Hypotheses.** Hyp. 1 to Hyp. 5 were fixed before the executable-harness experiments were run; Hyp. 6 and Hyp. 7 were specified for the extension study. Hyp. 1: deterministic enforcement is invariant to model susceptibility; guardrails are monotone in it. Hyp. 2: under adaptive, repeated attack guardrail success tends to 1 while a sound monitor plateaus at its policy residual. Hyp. 3: monitor implementation quality matters against attackers that fuzz arguments. Hyp. 4: a sound monitor's residual is dominated by in-policy semantic manipulation. Hyp. 5: deterministic enforcement costs utility mainly through policy incompleteness. Hyp. 6: a human layer helps only behind a deterministic monitor, and over-escalation degrades it through fatigue. Hyp. 7: a deterministic approval budget restores a bound against approval spamming.

## 2. Related work

**Attacks, benchmarks and guidance.** Indirect prompt injection was characterised for LLM-integrated applications by Greshake et al. {c('greshake')}, following the direct goal-hijacking and prompt-leaking attacks on GPT-3 of Perez and Ribeiro {c('perez')}. The threat is now catalogued by the NIST adversarial machine-learning taxonomy {c('nist100')} and by the OWASP list of risks specific to agentic applications {c('owasp')}. Benchmarks measure it on tool-using agents: InjecAgent {c('injecagent')} provides 1,054 test cases, AgentDojo {c('agentdojo')} 97 tasks and 629 security test cases, ASB {c('asb')} a broader attack-and-defence suite, WASP {c('wasp')} realistic web-agent hijacking objectives and AgentDyn {c('agentdyn')} dynamic, open-ended tasks; Liu et al. {c('liu24')} formalise attacks and defences and benchmark five attacks and ten defences across ten LLMs.

**In-band defences and adaptive attackers.** Prompt-level defences ask the model itself to resist: instruction hierarchies {c('wallace')} train models to ignore lower-privileged instructions, spotlighting {c('hines')} marks the provenance of untrusted input and was reported to cut attack success on GPT-family models from above 50% to below 2% against a static attack set, StruQ {c('struq')} separates prompt and data with structured queries and a fine-tuned model, and SecAlign {c('secalign')} trains the same separation by preference optimisation. Whether models can separate instructions from data at all is contested: Zverev et al. {c('zverev')} introduce a formal measure of separation and find that the evaluated models separate them poorly. Adaptive attackers undermine such defences: Nasr et al. {c('nasr')} bypass 12 recent defences with success above 90% for most of them although most had reported near-zero rates, Zhan et al. {c('zhan25')} bypass eight defences against indirect injection on agents with success above 50%, and Jia et al. {c('jia25')} show that the fine-tuning defences StruQ and SecAlign fall to adaptive attacks and lose utility, and that detectors judged by AUC alone are misleading. This follows the general lesson of the adversarial-example literature that a defence must be evaluated against attacks designed for it {c('tramer')} and motivates our adaptive and compromised-model attackers.

**Out-of-band defences.** Architectural defences move the security decision out of the model. CaMeL {c('camel')} extracts control and data flow from the trusted query and enforces capability-based policies at tool calls, solving 77% of AgentDojo tasks with provable security against 84% for an undefended system; FIDES {c('fides')} tracks confidentiality and integrity labels in a planner and enforces policies deterministically; Progent {c('progent')} provides programmable privilege control over tool calls; AgentSpec {c('agentspec')} provides customisable runtime enforcement of rules over agent actions; Conseca {c('conseca')} generates context-specific security policies; IsolateGPT {c('isolategpt')} isolates the execution of agentic applications; MELON {c('melon')} detects injection by re-running the agent on a masked user prompt and comparing the tool calls; the Task Shield {c('taskshield')} checks every instruction and tool call for alignment with the user's task; and Beurer-Kellner et al. {c('patterns')} catalogue six design patterns. A recent preprint {c('narisetty')} re-evaluates an out-of-band defence under an adaptive attack with an open-weights agent. Our study differs in what it holds constant and what it adds: every defence family is judged by one effect-based oracle against one attacker model, argument-level implementation quality and policy completeness are varied explicitly, human-approval and taint-tracking layers are added, and the results are checked on real open-weights models.

**Foundations.** The conceptual roots are the reference monitor {c('anderson')}, the protection design principles of Saltzer and Schroeder {c('saltzer')}, capability-based addressing {c('dennis')}, the confused-deputy problem {c('hardy')}, which an injected agent re-creates, and lattice-based information flow {c('denning')}. Zero-trust architecture {c('nist207')} and operational-technology security guidance {c('nist80082')} supply the deployment context. Our monitors are deliberately simple instances of this tradition and not re-implementations of any one system.

## 3. Threat model

*Assets.* Read tools (`fetch_url`, `read_file`, `read_email`, `query_db`, `list_files`) are the injection channel; side-effecting tools (`send_email`, `http_post`, `write_file`, `delete_file`, `update_config`, `set_setpoint`, `run_shell`) are the targets. The user's request is the only trusted statement of intent.

*Attackers.* A0 naive; A1 authority-spoofing; A2 obfuscated/delimiter-spoofing; A3 adaptive (strength grows with attempts, guardrail effectiveness erodes, three argument variants per attempt, blocked variants remembered); A4 fully compromised model (obeys with probability 1 and tries the whole attack library with every variant, including approval spamming).

*Trusted base.* Monitor, policy, tool implementations, taint tracker and the approval channel. Out of scope: compromise of those, covert channels, denial of service.

*Objective.* No executed side-effecting call may differ from what the user's request authorises, judged by an oracle that canonicalises arguments and never consults a defence.

## 4. Defences under test

| Key | Defence | Deterministic |
|---|---|---|
| D0 | No defence | no |
| D1 | In-prompt guardrail | no |
| D2 | Guardrail + spotlighting | no |
| D3 | Spotlight + LLM detector | no |
| D4 | P1 tool allow-list | yes |
| D5 | P2n naive argument checks | yes |
| D6 | P2h hardened argument checks | yes |
| D7 | P3 task-bound capabilities + confidentiality flow rule | yes |
| D8 | P3 + spotlight + detector | partly |
| H1 | P3 + human approval for severity >= 8 | no (human) |
| H2 | P3 + human + taint: when the session is tainted, severity >= 3 also needs approval | no (human) |
| H3 | P2h + human + taint (no capabilities) | no |
| H4 | P1 + human + taint | no |
| H5 | Human + taint only (no monitor) | no |

*Table 1. Defences under test.*

**Severity.** write_file 3, send_email 5, delete_file 7, http_post and run_shell 8, update_config and set_setpoint 9; egress carrying confidential data 10. Severity is per tool, not per content, so a semantically false write is rated 3; an operator who rates such content higher should lower `taint_thr` accordingly.

**Human approval.** Calls that pass the monitor and have severity >= `human_thr` (8), or >= `taint_thr` (3) while the session is tainted, are escalated. A reviewer misses a violating call with probability 1 - h, h = h0 · max(0.3, 1 − 0.3·L) · 0.93^k, where L is the mean benign escalations per task (fatigue) and k counts earlier attempts in the campaign plus earlier escalations in the episode (approval spamming); h0 = 0.9. Benign calls are falsely rejected with probability 2%. **Taint** survives with probability 0.95 in attack episodes; 40% of benign episodes ingest untrusted content. **Approval budget** (optional): after a fixed number of escalations in one episode further escalations are denied automatically.

## 5. Methodology

**5.1 Environment (real code).** Thirteen task templates with benign plans of one to three calls and an injection carried by a read step; attacks either add calls or rewrite the next planned call, with argument-level evasions (recipient lists, suffix confusion, userinfo URLs, path traversal, key-case changes, numeric-string setpoints, shell chaining). The oracle, the monitors and the attacker's variant search are executed code.

**5.2 Untrusted model (simulated).** At the first decision point after an injected output the model obeys with probability sigma(a0 + u_task + b·s − delta), s the attack strength, u_task a per-task offset, delta the guardrail reduction (1.5 prompt, 2.3 with spotlighting); defaults a0 = -1.1, b = 1.0. **These are assumptions**; Sections 6.2 and 5.5 address them.

**5.3 Benign variability.** Formatting variants (12%), extra reads (10%), scratch writes (5%), legitimate actions no static policy anticipated (5%); after a denial the agent retries with probability 50%.

**5.4 Metrics.** ASR = share of attack episodes (or campaigns) with any unauthorised side effect. **Harm** = the worst severity executed (0-10), averaged over episodes; **severe rate** = share with harm >= 8. Benign completion, false-block rate, escalations per task. Experiments: C1 main comparison; C2 threshold sweep; C3 taint-coverage failure; C4 policy-coverage failure x layering; C5 reviewer fatigue and spamming; C6 model-susceptibility sweep; C7 approval budget. Experiments E1-E6 of the executable harness (main comparison, susceptibility sweep, policy-coverage sweep, utility, 200 random parameterisations of the assumed model, bypass matrix; `results.json`) are reported alongside. With all new layers off the extended episode loop reproduces the base loop bit-for-bit (`test_equivalence.py`).

**Statistical methods.** Proportions carry Wilson 95% intervals {c('wilson')}; differences of proportions carry Newcombe-Wilson hybrid-score intervals {c('newcombe')}; families of tests use Holm's sequentially rejective correction {c('holm')}; agreement between the automatic oracle and hand labels, and between the two human raters, is Cohen's kappa {c('cohen')} with a percentile bootstrap interval (5,000 resamples), and agreement among the three label sources is Fleiss' kappa {c('fleiss')}.

**5.5 Real-model calibration.** `calibrate_real_model.py` measures how often an open-weights instruction model obeys an injected inert tool call at six attack strengths with and without in-prompt guardrails, fits logit p = a0 + b·s − delta by regularised maximum likelihood with a cluster bootstrap, and returns a calibrated `Params`. Its self-test with a fake model of known parameters (a0 = -1.1, b = 1.0, delta = 1.5) recovered a0 = -0.76 [-1.40, -0.19], b = 0.67 [0.36, 1.01], delta = 1.49 [1.02, 1.96]; re-running the simulation with those fitted values changed single-attempt rates by about 2-3 points and left the deterministic-layer conclusions unchanged. A first real-model run is reported, with its caveats, in Section 6.10.

## 6. Results

### 6.1 Main comparison (Hyp. 2)

{t1}
*Table 2. A2 = obfuscated injection (single attempt), A3 = adaptive campaign of up to 25 attempts, A4 = compromised model. Harm is the mean worst executed severity (0-10). Utility columns come from attack-free episodes.*

![Figure 1. Worst-case harm and severe-action rate by defence under the adaptive attacker (A3, 25 attempts) and the compromised model (A4).](figures_combined/fig1_harm_by_defence.png)

Against single non-adaptive attempts guardrails work as designed (A2 ASR falls from {p(g('D0','A2_asr'))} to {p(g('D3','A2_asr'))} with spotlight + detector). Persistence changes this: D1 to D3 reach {p(min(g(k,'A3_asr') for k in ('D1','D2','D3')))} adaptive ASR and the same harm as no defence ({g('D1','A3_harm'):.2f}), and under A4 they offer no protection (these simulated stacks assume that guardrail strength erodes with attempts; Section 6.11 tests that assumption on real models). P3 (D7) reduces A3 harm to {g('D7','A3_harm'):.2f} and A4 harm to {g('D7','A4_harm'):.2f} with zero severe actions. D8 (adding guardrails to P3) lowers A2 ASR to {p(g('D8','A2_asr'))} but leaves the worst-case bound unchanged (A4 ASR {p(g('D8','A4_asr'))}, same as D7) and costs {p(g('D7','completion')-g('D8','completion'))} of benign completion.

### 6.2 Invariance to model susceptibility (Hyp. 1)

{t6}
*Table 3. A2 ASR@1 as the baseline susceptibility a0 of the model sweeps from -4 to 4.*

![Figure 2. Single-attempt attack success as the model's baseline susceptibility varies.](figures_combined/fig7_susceptibility.png)

Guardrail ASR is strongly monotone in susceptibility (D1: {p(C6[C6.config=='D1'].A2_asr.min())} to {p(C6[C6.config=='D1'].A2_asr.max())}); the monitor-based defences move only through the share of attempts where the model does not cooperate, and under A4 their ASR is exactly independent of the model (checked by test). Across the 200 random parameterisations of the assumed model (experiment E5) D7 stays between {p(_pct('D7',5,95)[0])} and {p(_pct('D7',5,95)[1])} adaptive ASR at five attempts (5th to 95th percentile) while D1 spans {p(_pct('D1',5,95)[0],0)} to {p(_pct('D1',5,95)[1],0)}.

### 6.3 Implementation quality (Hyp. 3)

Of {nv} effective attack variants, a monitor in isolation would admit {adm['P1']} (P1 allow-list), {adm['P2n']} (P2n naive), {adm['P2h']} (P2h hardened) and {adm['P3']} (P3). Against the fuzzing adaptive attacker the naive monitor reaches {p(g('D5','A3_asr'))} ASR@25 and the hardened one {p(g('D6','A3_asr'))}, while against non-fuzzing attackers they are indistinguishable. This ladder measures the effectiveness of argument validation with executed code instead of assuming it (compare Section 6.9).

| Monitor | Effective variants admitted | Share |
|---|---|---|
| P1 tool allow-list | {adm['P1']} of {nv} | {p(adm['P1']/nv,0)} |
| P2n naive argument checks | {adm['P2n']} of {nv} | {p(adm['P2n']/nv,0)} |
| P2h hardened argument checks | {adm['P2h']} of {nv} | {p(adm['P2h']/nv,0)} |
| P3 capabilities + IFC | {adm['P3']} of {nv} | {p(adm['P3']/nv,0)} |

*Table 4. Effective attack variants each monitor would admit in isolation.*


### 6.4 What remains behind a sound monitor (Hyp. 4)

P3 eliminates exfiltration, unauthorised state change and OT setpoint abuse; what remains is in-policy semantic manipulation (a permitted report write that is false; a permitted email whose body carries a phishing link). Under A4 the residual is {p(g('D7','A4_asr'))} of episodes but only {g('D7','A4_harm'):.2f}/10 harm, because it consists of low-severity tools. This residual cannot be reduced by more argument checking.

### 6.5 Human approval and taint: what helps and what does not (Hyp. 6)

*Sections 6.5 to 6.7 are simulation-only: the reviewer model, severity scale and taint-tracking failure model are assumptions, not measurements.*

H1 (severity-gated approval on top of P3) equals D7 on every attack metric, because P3 has already blocked every call that reaches severity 8. The gain comes from taint-triggered review of in-policy actions: H2 reduces A4 harm from {g('D7','A4_harm'):.2f} to {g('H2','A4_harm'):.2f} and A4 ASR from {p(g('D7','A4_asr'))} to {p(g('H2','A4_asr'))}, at {g('H2','esc'):.2f} escalations per benign task and {p(g('D7','completion')-g('H2','completion'))} lower completion.

A4 harm over the gate thresholds (H2):

{t_thr_h}
*Table 5. A4 harm of H2 as the human-approval threshold (rows) and the taint threshold (columns) vary.*

Escalations per benign task:

{t_thr_e}
*Table 6. Human escalations per benign task on the same grid.*

Raising `taint_thr` above the severity of in-policy writes (3) removes the benefit (harm back to {g('D7','A4_harm'):.2f}); raising `human_thr` while keeping `taint_thr` = 3 cuts workload by {100*(1-_w10.esc/_w8.esc):.0f}% with little loss (human_thr 8 to 10: {_w8.esc:.2f} to {_w10.esc:.2f} escalations, harm {_w8.A4_harm:.2f} to {_w10.A4_harm:.2f}).

![Figure 3. Threshold sweep for the human-approval and taint gates: harm, workload and utility.](figures_combined/fig2_threshold_sweep.png)

Over-escalation is not free: reviewer fatigue and approval spamming raise the residual. For H2, A4 harm grows from {C5[(C5.config=='H2')&(C5.fatigue==0)&(C5.spam_decay==1.0)].A4_harm.iloc[0]:.2f} (no fatigue, no spamming effect) to {C5[(C5.config=='H2')&(C5.fatigue==0.5)&(C5.spam_decay==0.8)].A4_harm.iloc[0]:.2f} (strong fatigue, spam decay 0.8):

{t_fat}
*Table 7. A4 harm of H2 as reviewer fatigue (rows) and approval-spam decay (columns) vary.*

### 6.6 A human layer is not a boundary on its own (Hyp. 6, Hyp. 7)

H5 (human + taint, no monitor) stops many attempts but fails against a compromised model that spams the reviewer: {p(g('H5','A4_sev'))} severe actions and harm {g('H5','A4_harm'):.2f}. Even with no fatigue and no spamming decay it reaches {p(C5[(C5.config=='H5')&(C5.fatigue==0)&(C5.spam_decay==1.0)].A4_sev.iloc[0])} severe actions, because repeated requests eventually succeed when each has a small miss probability.

A4 severe-action rate for H5:

{t_fat5}
*Table 8. A4 severe-action rate of H5 (human and taint, no monitor) under the same fatigue and spam settings.*

A deterministic **approval budget** (automatic denial after n escalations in one episode) restores a bound:

{t7}
*Table 9. Effect of a deterministic approval budget per episode.*

![Figure 4. Effect of a deterministic approval budget on severe actions, harm and benign completion.](figures_combined/fig5_approval_budget.png)

A budget of 1 to 2 cuts H5's A4 harm from 10.0 to {C7[(C7.config=='H5')&(C7.esc_cap=='1')].A4_harm.iloc[0]:.1f}-{C7[(C7.config=='H5')&(C7.esc_cap=='2')].A4_harm.iloc[0]:.1f} and H2's from {C7[(C7.config=='H2')&(C7.esc_cap=='none')].A4_harm.iloc[0]:.2f} to {C7[(C7.config=='H2')&(C7.esc_cap=='1')].A4_harm.iloc[0]:.2f} at a cost of {_cost('H2','1'):.1f} points of benign completion for H2, and {_cost('H5','2'):.1f} (budget 2) to {_cost('H5','1'):.1f} points (budget 1) for H5. The residual for H5 shows why the monitor, not the human, must carry the guarantee.

### 6.7 Failure of taint tracking and of the policy

A4 harm as taint coverage falls:

{t_cov}
*Table 10. A4 harm as taint-tracking coverage falls.*

A4 severe-action rate:

{t_covs}
*Table 11. A4 severe-action rate as taint-tracking coverage falls.*

![Figure 5. Harm and severe-action rate as taint-tracking coverage falls.](figures_combined/fig3_taint_coverage.png)

Harm degrades gradually toward the bound of the layer beneath: H2 returns to P3's bound ({g('D7','A4_harm'):.2f}) at zero taint coverage and no further. With a weaker monitor (H3, hardened arguments only), moving the human gate from severity 8 to 10 saves workload but its severe rate rises from {p(C3[(C3.config=='H3 human_thr=8')&(C3.taint_cov==0.0)].A4_sev.iloc[0])} to {p(C3[(C3.config=='H3 human_thr=10')&(C3.taint_cov==0.0)].A4_sev.iloc[0])} when taint tracking fails: independent layers should fail safe, so efficiency changes that make one layer depend on another should be avoided.

Policy incompleteness degrades the monitor roughly in proportion to what is missing, and layering helps at every coverage level but cannot repair a missing policy:

{t_pol}
*Table 12. A4 harm; each policy rule present with probability c. The H5 column is constant because it has no monitor.*

![Figure 6. Harm as policy-rule coverage falls, for the monitor alone and with each added layer.](figures_combined/fig4_policy_coverage_layering.png)

### 6.8 Security-utility trade-off (Hyp. 5)

![Figure 7. Harm against benign completion (left) and against human workload (right).](figures_combined/fig6_pareto.png)

On the harness, utility differences are small (benign completion {p(C1.completion.min())} to 100%) while A4 harm spans from {C1.A4_harm.min():.2f} to {C1.A4_harm.max():.0f}, so the decision is dominated by security except for the human workload ({_esc.min():.1f} to {_esc.max():.1f} escalations per task) and, for guardrail stacks, the detector's extra model call per task (D3 completion {p(g('D3','completion'))}).

### 6.9 Consistency check against a separately built abstract model

As a consistency check, a separately built abstract Monte Carlo model (no real tools; five tool classes with assumed monitor effectiveness; severity-weighted harm; a human gate with fatigue and spamming; taint coverage) was run on the same questions. The two models agree on the qualitative structure: deterministic gating bounds harm even for a compromised model; layering guardrails on a deterministic layer does not move the worst-case bound; the residual is in-policy behaviour; a taint layer is useful but must not be load-bearing; and the human gate belongs behind, not instead of, the deterministic layer. They share design assumptions, so this is a consistency check and not independent validation. They disagree on guardrail persistence: in the abstract model spotlighting, with or without a detector, stays well below 100% under persistence (about 22-45% across its adaptive and aware attackers; the prompt guardrail reaches 99.5% at 10 attempts), while in the executable harness every guardrail stack reaches 100% because guardrail strength is assumed to erode with attempts. The real-model results in Section 6.11 should be read against both. Absolute values are not comparable across the two models because their environments and metrics differ. The abstract model's assumed argument-validation catch rates (0.5 to 0.95) are consistent with the measured implementation ladder here (naive {p(1-adm['P2n']/nv,0)}, hardened {p(1-adm['P2h']/nv,0)}, capability-bound {p(1-adm['P3']/nv,0)} of effective variants blocked).

### 6.10 Real-model check and empirical re-run

**Measurement.** An open-weights instruction model (Qwen/Qwen2.5-1.5B-Instruct) was given a summarisation task with an injected, inert tool call at six attack levels, with and without an in-prompt guardrail (174 prompts, two samples each; 24 samples per level-by-guardrail cell). Attack success is the model emitting the injected tool call with the attacker string in its arguments. The per-cell counts used below were reconstructed from the rates printed by the calibration run (rate × 24, which round exactly to integers); the raw sample log was not retained, so the intervals and tests in this subsection cannot be re-derived from the original samples.

| **Level** | **0** | **1** | **2** | **3** | **4** | **5** |
| --- | --- | --- | --- | --- | --- | --- |
| No guardrail | 4.2% | 20.8% | 50.0% | 4.2% | 0.0% | 4.2% |
| Guardrail G1 | 0.0% | 16.7% | 45.8% | 4.2% | 8.3% | 0.0% |

*Table 13. Measured obedience by attack level and guardrail (n = 24 per cell; 95% intervals are about ±20 points, e.g. level 2: 31%-69%).*

**Findings.** (1) The simulator's monotone logistic law is rejected: deviance against a saturated model is 60.3 on 9 degrees of freedom (p = 1e-09); testing monotone-in-level against level-specific rates gives p = 4e-11. The levels are different attack families, not points on one strength scale: the "document owner requires" phrasing (level 2) reaches 50%, while the "urgent system notice, do not mention" phrasing (level 3) reaches 4%. (2) The guardrail effect is not detectable: pooled 20/144 without versus 18/144 with the guardrail (Fisher p = 0.86); a common guardrail shift has estimate +0.16 in log-odds (LRT p = 0.69), against the 1.5 to 2.3 assumed in the simulator. (3) At levels 4 and 5 only 58% and 50% of outputs parse as tool calls; the remainder contain no brace at all (so truncated JSON is ruled out) and show no refusal language. Parsed outputs at those levels are almost never the attacker's call. The cause of the non-JSON outputs (plain-text summaries or echoed markup) has not been inspected and the near-zero obedience there should not be read as robustness. (4) Repeated attempts are close to independent (dispersion ratio 1.24).

**Empirical re-run.** The harness was re-run with the simulated obedience replaced by these measured per-family rates, with Beta posterior uncertainty propagated through 60 replicate draws (tools, oracle, monitors and fuzzing unchanged). An attacker who knows the best family (level 2) succeeds per attempt with probability about 50% (no guardrail) or 46% (guardrail), i.e. cumulative obedience of 86.1% (67.9-96.9) after 3 attempts and 99.6% (97.7-100.0) after 10 without the guardrail (99.4% (96.1-100.0) with it). If the attacker merely resends one prompt, clustering lowers this to 93.6% (82.2-98.9) after 10 attempts.

| Defence | Empirical best-family k=1 | k=3 | k=10 | Empirical search k=10 | Original logistic A3 k=10 | Compromised model (emp.) |
|---|---|---|---|---|---|---|
| D0 None | 50.9% (33.8–64.3) | 87.0% (73.7–95.7) | 99.8% (98.6–100.0) | 83.6% (72.3–91.3) | 100.0% | 100.0% (100.0–100.0) |
| D1 Prompt | 45.4% (28.0–60.2) | 82.7% (65.5–93.4) | 99.5% (97.2–100.0) | 79.8% (68.3–88.6) | 100.0% | 100.0% (100.0–100.0) |
| D2 Spotlight* | 45.6% (30.0–62.6) | 83.1% (67.8–93.9) | 99.5% (96.8–100.0) | 80.2% (70.1–88.0) | 100.0% | 100.0% (100.0–100.0) |
| D3 Spot+Det* | 18.6% (11.7–27.0) | 45.9% (32.6–59.5) | 86.5% (71.9–95.7) | 46.0% (35.4–56.2) | 99.8% | 100.0% (100.0–100.0) |
| D4 P1 | 43.0% (28.1–56.2) | 74.2% (60.5–81.6) | 84.4% (83.5–84.6) | 71.0% (62.4–77.2) | 84.6% | 92.3% (92.3–92.3) |
| D5 P2n | 42.6% (28.9–56.5) | 73.7% (60.1–81.8) | 84.4% (83.2–84.6) | 71.0% (62.3–78.6) | 84.6% | 92.3% (92.3–92.3) |
| D6 P2h | 15.6% (10.3–20.6) | 26.6% (21.8–29.7) | 30.7% (30.2–30.8) | 25.8% (22.9–28.3) | 30.8% | 61.5% (61.5–61.5) |
| D7 P3 | 4.2% (2.3–6.3) | 6.8% (5.5–7.7) | 7.7% (7.7–7.7) | 6.4% (5.1–7.7) | 7.7% | 23.1% (23.1–23.1) |
| D8 Layered* | 1.5% (0.3–2.9) | 3.6% (2.3–5.2) | 6.6% (5.2–7.7) | 3.5% (2.5–4.9) | 7.7% | 23.1% (23.1–23.1) |

*Table 14. Full-harness ASR (mean and 95% posterior interval) with measured obedience. Best family = level 2; search = a uniformly random family per attempt. **Spotlighting (D2, D8) uses the measured prompt-guardrail rates and the detector (D3, D8) a fixed assumed true-positive rate of 0.6, because neither was measured.***

The monitor results are unchanged by the empirical rates (P2h 30.7%, P3 7.7% at k = 10; compromised model 23.1% for P3), as expected, since they do not depend on the model. For guardrail-only defences the empirical rates support the earlier qualitative conclusion: the guardrail changes ten-attempt success from 99.8% to 99.5%, i.e. not measurably. The one number that moves materially is the detector stack (D3): 86.5% at ten attempts with an assumed detector against 99.8% under the old logistic erosion, which shows that conclusion depends on an unmeasured detector assumption.

**What this does and does not establish.** It establishes that, for one 1.5B-parameter model and one task type, the assumed logistic law is wrong in shape and the assumed guardrail strength is too high, and that per-attempt obedience near 50% is enough to make persistent attacks succeed. It does not establish how stronger models, spotlighting or detectors behave, nor does it test any monitor, taint or approval layer against a real model.

{PIL['sec611']}## 7. Discussion

**Form of the security argument.** A guardrail's argument is that the model is unlikely to obey; it fails against persistence and a compromised model {c('nasr','zhan25')}. A monitor's argument is that the permitted action set is bounded and the model is outside the trusted base {c('anderson','saltzer')}. An injected agent is a confused deputy {c('hardy')}: it holds the user's authority and is steered by an attacker's data, and capabilities {c('dennis')} bound that authority to what the task needs; zero-trust architectures likewise grant no implicit trust {c('nist207')}. That turns an adversarially unstable empirical question into an engineering one: is the policy right, is the code right.

**Design rules suggested by the results** (rules 2 and 3 rest on the simulation-only human model)**.** (1) Put the guarantee in a deterministic, capability-bound monitor, hardened against argument tricks. (2) Use human approval for what the monitor cannot decide (semantic content), triggered by taint rather than by tool severity alone. (3) Give the approval channel a deterministic budget and rate limit. (4) Keep layers independent so that each fails safe. (5) Treat guardrails as noise reduction: they cut attempted violations (A2 ASR {p(g('D7','A2_asr'))} to {p(g('D8','A2_asr'))} when added to P3) but not the worst case.

{PIL['discussion']}

**Where it does not help.** Semantic manipulation within permitted actions when no human can judge it; policies that cannot be derived from user intent without an LLM; covert channels; legitimate arguments that originate in untrusted data.

**Industrial settings.** Setpoint, configuration and shell actions have enumerable schemas, the regime in which deterministic policies are most tractable; operational-technology security guidance already requires that controls respect performance, reliability and safety constraints {c('nist80082')}. For an agent near a control system the results suggest a layered pattern: a per-task tool allow-list; numeric bounds and tag scoping for actuation; no outbound channel after confidential reads; a deterministic budget on approval requests; and human review reserved for what a policy cannot decide, such as the content of reports. These are design implications of a simulation-based study and have not been validated on an operational system.

## 8. Limitations

{PIL['limitation']}
2. **Oracle/policy coupling.** P3's capabilities equal the oracle's authorisation set, so its near-zero residual on covered classes is partly by construction; the informative quantities are the residual classes, coverage degradation and the implementation ladder.
3. **Human model.** The reviewer is modelled as an oracle with a miss probability that decays with load and spamming; real reviewers differ and may rubber-stamp, and qualitative studies of security analysts report an alarm-validation burden and burnout {c('alahmadi')}. Severity is per tool, not per content.
4. **Task suite.** Thirteen tasks written by the authors; classes are not weighted by real-world frequency.
5. **Session-level taint.** Taint is assigned at session level by the harness; real systems must propagate it through model-generated values.
6. **Benign behaviour** after denials is stylised. No multi-agent or multimodal settings.
7. **Real-model coverage.** Only open-weights models up to 7B parameters were tested, with static attack families; no frontier model and no attacker that optimises against the detector or the monitor.

## 9. Reproducibility and availability

```
python test_equivalence.py              # invariant tests
python run_experiments.py               # executable harness E1-E6 (~2 min)
SCALE=1 python combined_experiments.py  # C1-C7 (~2 min)
python make_figures_combined.py         # figures
python pilot_real_v1/analyze_pilot.py   # real-model pilot tables and figure
python pilot_real_v2/analyze_v2.py \\
    pilot_real_v2/data/episodes_all.csv   # Tables 15-18 from the raw log
python make_latex.py                    # arXiv LaTeX package
cd pilot_real_v2/oracle_audit && python -I score_second_rater.py ../.. KEY.csv \\
    sheet_V1_raterB.xlsx sheet_V2_raterB.xlsx    # two-rater oracle audit
python make_paper_combined.py           # regenerate this manuscript
python make_docx.py                     # Word version
```
Dependencies: Python >= 3.10, numpy, scipy, pandas, matplotlib, openpyxl (torch, transformers, accelerate for real-model runs). Seeds are fixed (20261026; real-model runs 20261027; audit-sheet shuffling 20261103). The shipped `results.json` and `results_combined/` were produced by these commands and every number in Sections 6.1-6.9 is read from them when the manuscript is regenerated.

**Real-model runs.** `notebooks/realllm_agentsec_eval_v2.ipynb` (Colab, GPU) runs the end-to-end evaluation at three scales and exports `results_pack.zip`; `pilot_real_v1/analyze_pilot.py` regenerates the pilot tables from the log in `pilot_real_v1/data/`, and `pilot_real_v2/analyze_v2.py` does the same for a notebook `results_pack.zip` (when present, Section 6.11 and the abstract use it automatically); the analysis plan was written before the larger run and is in `ANALYSIS_PLAN.md`; `empirical/` re-runs the harness with the measured per-family obedience of Section 6.10.

## Declarations

**Author contributions (CRediT).** M.S.A.: conceptualisation, software, investigation (simulation and real-model runs), data curation, formal analysis, validation (oracle audit, rater A), visualisation, writing of the original draft. N.S.A.: conceptualisation (research idea), methodology (the enforcement algorithm, the design of the experiments, review of the methodology), validation (independent blind oracle audit, rater B), writing (review and editing). R.A.: supervision, methodology (review of the methodology), and discussion and interpretation of the results. All authors discussed the defences and the results and approved the final manuscript.

**Competing interests.** The authors declare no competing interests.

**Funding.** This work received no external funding.

**Employer and data.** M.S.A. is employed by Missan Oil Company (Iraq) as its AI and cybersecurity lead and publishes under that affiliation. No confidential, proprietary or operational data or documents of the company were used; every task, tool, document and data item in the study is synthetic.

**Data and code availability.** The complete package (simulation code, raw real-model logs, analysis scripts, the two-rater oracle-audit sheets and scores, the Colab notebook and the analysis plan) is available at https://github.com/nawaralseelawi/untrusted-model-agentsec (release v1.0.0 corresponds to this version of the manuscript).

**Use of AI assistants.** AI language-model assistants were used to help write and debug the simulation and analysis code, to propose experiment designs, to check references and to draft and edit text. The authors specified the research question, ran the real-model experiments, labelled the oracle audits and are responsible for the content.

**Responsible use.** All tools in the environment are inert simulations, the injection texts are generic patterns, and no vulnerability in a deployed product is disclosed.

## References

{_cite.reflist()}
"""
if os.environ.get("CITE_MODE") == "latex":
    md = md.split("\n## References\n")[0]
    open("_paper_cite.md", "w").write(md); open("references.bib", "w").write(_cite.bib()); print(len(md), "chars (latex mode)", len(_cite.order), "references")
else:
    open("paper_combined.md", "w").write(md); print(len(md), "chars")
