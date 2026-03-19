# Readability Review: tinyp256.tex

**Target reader:** knows programming, does NOT know elliptic curves or x86 assembly optimization.
**Abstract's promise:** "No prior exposure to elliptic curves is assumed."

Build: ✅ compiles (one cosmetic underfull hbox at L1344-1347, pre-existing).

---

## 1. Undefined jargon

### Tier A — genuinely blocks understanding

| Line | Term | Problem | Fix |
|---|---|---|---|
| 131 | "the order of $G$" | Group-theoretic jargon. A programmer has no idea a point can have an "order." | Add parenthetical: "(the smallest $k$ with $k \cdot G = \mathcal{O}$)" — or just "(another 256-bit prime; don't worry why it's called that)". |
| 379 | "affine $x$-coordinate" | "Affine" appears here as an adjective with no definition. Prior §1.2 said "works with $(x,y)$ pairs directly" — that IS affine, but the word was never attached. | Either add "affine (i.e. ordinary $(x,y)$)" here, or tag L147 "working with $(x, y)$ pairs directly — the \emph{affine} representation —". |
| 415 | "discrete log problem" | Assumed knowledge. Non-EC reader won't know this is THE hardness assumption underlying ECDSA. | "as hard as the discrete log problem — the computational assumption the whole scheme rests on." (Tiny edit; already almost says it.) |
| 441, 456 | `bt` instruction | Section title and body use `bt` as if known. Never expanded to "bit test". | Add on first body use (L456): "with the `bt` (bit-test) instruction." |
| 822 | "REX prefix" | x86-64 encoding jargon, zero context. | "(a REX prefix — the extra byte x86-64 uses to reach registers r8–r15)". |
| 824 | "red zone" | ABI jargon. A programmer who hasn't read the SysV spec won't know. | "(the 128 bytes below `rsp` that the ABI promises won't be clobbered by signal handlers)". |
| 943 | "the ladder" | First use. §1.2 described scalar mult as "square-and-multiply style loop" — never called it a ladder. Crypto jargon. | Either "initialise the scalar-multiply loop (the \emph{ladder}) to a specific state" or drop "ladder" and say "loop" throughout §13.2. |
| 996, 998 | "limb", "limb width" | Used in §13.3 — but "limb" is only defined at **L1106 in §14.1**. | See §3 below (section-order issue). Either move the definition earlier or s/limb/word/ in §13.3. |
| 1198 | "lazy carrying" | Only occurrence. Never defined. §14.1 L1108 says "headroom for carries to accumulate between reductions" which IS the concept, but the term never links to it. | "with lazy carrying — letting carries accumulate in the headroom rather than propagating immediately — each add can grow..." |
| 1259 | `xlatb` | Never explained, AND the cross-ref "(§\ref{sec:grind})" points to §12 which **does not mention `xlatb`**. Broken reference. | Either drop the §12 ref, or add a one-line gloss: "`xlatb` (one-byte table lookup: `al ← [rbx+al]`)". |
| 1279 | "cancelling $R$-factors" | What is an $R$-factor? The only $R$ in the paper is L276 ($R = 2^{256}$ in Montgomery form) and it was introduced as something we got rid of. | Gloss: "cancelling $R$-factors in the projective check (the Montgomery $R$ scales both sides, so it drops out)". |
| 1280 | "signed-limb representation" | New concept, no gloss. All prior limbs were implicitly unsigned. | Gloss: "a signed-limb representation of $p$ (allow limbs to be negative, so $p$'s structure becomes $\pm 1$ entries)". |

### Tier B — speed-bump; reader can probably infer

| Line | Term | Problem | Fix |
|---|---|---|---|
| 172 | "32-bit limbs" | First use of "limb", in the table. Defined 934 lines later. | Probably fine in a table. Optionally: footnote, or reword to "32-bit words". |
| 175 | `mulx`, "Shamir's trick" | Table row, no explanation. Shamir explained in §8, `mulx` never. | Table forward-refs are tolerable. `mulx` could just be dropped from the row — it's not important to the story. |
| 383 | "Jacobian" | Mentioned as alternative ($X/Z^2$) but never explained why you'd pick one over the other. Comes back at L976 as "a different coordinate system (Jacobian)". | The formula-only mention at L383 is adequate. L976 is fine given L383. No change needed. |
| 458 | `enter`, `leave` | Assembly mnemonics, not glossed. | Context makes clear they're stack-frame instructions. Probably fine. |
| 1025 | "$j$-invariant" | Pure algebraic-geometry jargon inside a parenthetical. | Fine as-is — it's explicitly a dismissive aside ("and is not fixable"). Non-expert can skip it. |
| 1026 | "non-adjacent form, window methods" | Name-dropped jargon. | Fine — the sentence explains what they DO ("more digits are zero"), which is all the reader needs. |
| 1057 | `scasd` | Obscure even by x86 standards. | Fine — point is "we found a gadget, it's useless." Reader doesn't need to know what `scasd` does. |
| 1070 | "sign-extend instruction" | Not named. | Fine — generic enough. |
| 1204 | "growth chain" | One-off term. | Inferable from context ("$\times 12$ growth chain"). Fine. |
| 1206 | "converges" | Used loosely (not a limit, just "stays bounded"). | Borderline. Consider "fits" instead of "converges". |

### Tier C — FINE, no change

- L130 "generator" — scare-quoted and the reader only needs to know "it's a fixed point." Good enough.
- L236 `lodsw`, L237 `movzx` — inside a code listing with a comment explaining what happens. Fine.
- L869 "microcoded" — immediately glossed ("costs several extra cycles"). Fine.
- L871 "Skylake", "AMD Zen" — programmers will recognize these as CPU names even if they can't place the generation. Fine.
- L1021 "endomorphism" — scare-quoted and glossed in the same sentence. Model behavior.
- L1117 `rdx:rax` — explained right there ("two-register output of `mul`"). Fine.

---

## 2. Prose tells

### Emph density — overview

Computed `\emph{}` per 100 source lines, excluding the structural `\noindent\emph{From X to Y}` section headers (consistent formatting, not prose stress):

| § | Lines | Emphs | /100 | Notes |
|---|---|---|---|---|
| 1  | 93  | 12 | **12.9** | Outlier, but mostly term-definitions (legitimate). 3 vocal-stress. |
| 3  | 69  | 4  | 5.8 | |
| 4  | 103 | 8  | **7.8** | Has a 3-in-3-lines cluster. |
| 5  | 71  | 3  | 4.2 | |
| 6  | 65  | 2  | 3.1 | |
| **7** | 85 | 5 | 5.9 | **Historical problem section — now CLEAN.** |
| **8** | 48 | 2 | 4.2 | **Historical problem section — now CLEAN.** |
| **9** | 71 | 3 | 4.2 | **Historical problem section — now CLEAN.** |
| 10 | 38  | 3  | **7.9** | Has the one whole-sentence-italic punchline. |
| 11 | 64  | 1  | 1.6 | |
| 12 | 83  | 2  | 2.4 | |
| **13** | 197 | 6 | 3.0 | **New content — CLEAN.** |
| **14** | 196 | 3 | 1.5 | **New content — CLEAN. Lowest in paper.** |
| 15 | 40  | 0  | 0   | |

Median ≈ 4.2. The 1.5× threshold is ~6.3.

**Verdict on §§7–9:** The historical density drift is **fixed**. All three are now 4.2–5.9, squarely in the normal band. Whatever cleanup was done, it worked.

**Verdict on new §13–14:** No density problem. At 1.5–3.0/100 they're actually among the sparsest sections in the paper. The new content does not exhibit the tic.

### Vocal-stress italics on function words (the specific tell)

| Line | Snippet | Comment |
|---|---|---|
| 103 | `both smaller \emph{and} faster` | Function word. Drop — "both smaller and faster" reads the same. |
| 117 | `what the verifier \emph{does}` | Function word. Drop. |
| 154 | `loop that calls \emph{them}` | Function word. Drop. |
| 256 | `you don't \emph{have} 256 slots` | Function word. Drop. |
| 363 | `is \emph{not} all-ones` | Borderline — contrastive "not" after two positives. Probably earned. Keep. |
| 374 | `smaller \emph{and} faster` | In a header. Same as L103; drop. |
| 973 | `that add \emph{can} hit the edge cases` | Function word. Drop — the point is clear without it. |
| 1009 | `already \emph{is} the factored form` | **Classic vocal-stress tell.** Drop. |

L57 `\emph{why}`/`\emph{that}` — contrasting pair in the abstract, not vocal stress. Keep.
L361-362 `\emph{32-bit}` / `\emph{64-bit}` — contrastive technical precision. Earned. Keep.

### Labeled takeaways

| Line | Text | Comment |
|---|---|---|
| 497 | `\subsection{The broader lesson}` | Subsection header IS a labeled takeaway. Consider just "Specificity" or "Why this transfers" — let the content carry it. |
| 635 | `The general principle: data layout changes...` | Colon-labeled takeaway at paragraph start. Reword: "Data layout changes inside the bytecode are free..." — drop the label, keep the sentence. |
| 980 | `The lesson is not that...` | **This one is fine.** It's pre-empting a misreading, not labeling a takeaway. Keep. |

### Whole-sentence-italic punchlines

| Line | Text | Comment |
|---|---|---|
| 744–745 | `\emph{instruction scheduling in a data table to change register allocation to shrink an addressing mode in unrelated native code.}` | Whole-clause italic close to §10. The memory file says "one earned, two-in-a-row = tic." This is the only one in the paper — **probably earned** (it IS the payoff of a long setup). But if you want zero, drop the `\emph{}` and let the sentence speak for itself. |

No other whole-sentence italics found. One is fine.

---

## 3. Section-order issues

### §13.6 uses §14 vocabulary — CONCRETE PROBLEM

**L1067–1090 ("The non-portability of tricks")** makes sustained use of concepts introduced in §14:

| Line | Term used | Defined at |
|---|---|---|
| 1067 | "One of the Montgomery tracks" | L1212 (§14.5) — reader doesn't know there ARE parallel tracks yet |
| 1073, 1078, 1081, 1084 | "top limb", "five-limb tracks", "24-bit limbs" | L1106 (§14.1) |
| 1081–1083 | "top limb after carry propagation fits in 18 bits" | Echoes L1205 (§14.4) |

The cross-ref `(\S\ref{sec:limbs})` at L1067 is a **forward reference** — §13 ends at L1091, §14 starts at L1093. A reader at L1067 is being told "(see §14)" for something they need NOW to parse this subsection.

**Suggested fix (pick one):**
- **(a)** Move §13.6 to the end of §14 (after L1285), where all the vocabulary is available. It reads naturally as a §14 coda: "here's a cross-track trick that failed to port."
- **(b)** Keep it in §13 but open with one sentence of setup: "As §14 will detail, we also built three variants with different word sizes — \emph{limbs} — for the big integers. One of these found a neat consolidation..." and s/limb/word/ for the rest of the subsection.
- **(c)** Swap §13 and §14 entirely. §14 has no forward deps on §13 (checked: refs go only to §4, §7, §12, §13.1). Drawback: §13 → §15 flows better than §14 → §15 does.

Option (a) is cleanest.

### §13.3 uses "limb" — minor

**L996, L998** ("limb width", "one giant limb") — same issue as above but much milder. The subsection is otherwise self-contained. Fix: s/limb/word/ in these two spots would make it fully independent of §14.

### §13.3 assumes more Montgomery than §4 gave — minor

**L994–999:** "Montgomery reduction computes a correction factor by multiplying by a magic constant, $-p^{-1} \bmod 2^W$..." — §4's only Montgomery content was L275-288 saying "we dropped this." The magic constant appears at L280 as "$m_0^{-1} = -m^{-1} \bmod 2^{64}$" but its PURPOSE was never stated.

A non-expert reading §13.3 is asked to reason about why $c=1$ would be nice without having been told what $c$ does. §14.2 (L1151-1159) explains this much better ("what multiple of $p$ can I add so the bottom $W$ bits become zero").

**Suggested fix:** Either add one sentence at L995 ("— the multiple of $p$ that zeroes the low $W$ bits of the running product —") or simply cut L994-1007 (the computation at L1003 proves something the reader can't evaluate) and keep only L1009-1015 which stands on its own.

### L1259 cross-ref to §12 — BROKEN

**L1259:** "`xlatb` instruction for dispatch (§\ref{sec:grind})" — but §12 (L812-893) **does not mention `xlatb` anywhere**. The cross-ref points to nothing. See also Tier-A jargon entry above.

**Fix:** Drop "(§\ref{sec:grind})" and add a gloss instead.

### L148 forward-ref to §5 — FINE

"(see §\ref{sec:projcheck})" is a clear look-ahead; reader isn't expected to understand §5 yet. No problem.

### L264, L438 forward-refs — FINE

Both are "we'll use this later" teasers, clearly flagged as such. No problem.

---

## 4. New content (§13.2–13.6, §14.4) — close read

### §13.2 "Dropping Shamir's trick" (L930–984) — GOOD, with one jargon fix

The Hamburg theorem at L942-947 is explained well: "if you prepare the scalar carefully — force it odd, initialise the ladder to a specific state — then inside the loop the running point can never coincide with the base point or its negative." A non-expert can follow the IMPLICATION (edge cases go away) without knowing the proof.

The table (L951-962) is excellent — concrete byte-deltas with one-line reasons.

L969-978 explains each table row and a non-expert can track it given §§5-8.

**Only flag:** "ladder" at L943 (see Tier-A jargon). One-word fix.

### §13.3 "Single-kernel modular multiply" (L986–1015) — ROUGH, see §3 above

The deinterleaving concept (L988-992) is clear. But L994-1007 asks the reader to care about whether $-p^{-1} \bmod 2^{256}$ equals 1, using "limb" vocabulary they won't have and Montgomery mechanics §4 didn't cover. L1009-1015 (the real point: we already factored it, going the other way cost −7 B) is clear and stands alone.

**Verdict:** the first half works, the middle (L994-1007) is the weakest passage in the new content for a non-expert, the conclusion is fine.

### §13.4 "Scalar splitting" (L1017–1034) — FINE

Both bullets gloss their jargon inline ("endomorphism" at L1021, the effect of sparse recoding at L1027-1028). The $j$-invariant mention is buried in a parenthetical and doesn't block understanding. No changes needed.

### §13.5 "Finding bytecode hidden in other bytes" (L1036–1063) — FINE

Entertaining and self-contained. `scasd` at L1057 isn't glossed but doesn't need to be — "it advances rdi by four, we work in eight-byte words, useless" carries the point. No changes needed.

### §13.6 "Non-portability of tricks" (L1065–1090) — SECTION-ORDER PROBLEM

Content is good and the point (architectural coincidences compound) is well made, but it's un-parseable without §14. See §3 above.

### §14.4 "Proving the limbs don't overflow" (L1188–1210) — GOOD, with one jargon fix

L1190-1194: clear setup, ties back to a concrete failure in §13.1. Good.

L1196-1207: dense but honest. A non-expert can follow: "43 operations, each add can grow limbs, question is whether anything overflows 64 bits, we check symbolically." The specific numbers (29 bits, $\times 12$, $2^{258}$, 264 vs 260) are there for verification, not required for the argument.

**Only flag:** "lazy carrying" at L1198 (see Tier-A jargon). Two-word parenthetical fixes it.

L1208-1210: clean close. The build fails if the bounds don't hold — a programmer will appreciate this.

---

## Summary

| Category | Count | Severity |
|---|---|---|
| Tier-A undefined jargon | 12 | Mostly 1-parenthetical fixes |
| Tier-B jargon | ~10 | Inferable; optional polish |
| Vocal-stress italics on function words | 6 to drop, 2 to keep | Mechanical fix |
| Labeled takeaways | 2 | (L497, L635) |
| Whole-sentence italics | 1 | Probably earned; optional |
| Section-order | **1 real** (§13.6 ↔ §14), 1 minor (§13.3), **1 broken cross-ref** (L1259) | §13.6 needs moving or rewording |
| §§7–9 historical emph drift | **Fixed** | No action |
| New §13–14 emph density | **Clean** (1.5–3.0/100, below median) | No action |

The paper delivers on its "no prior EC exposure" promise through §12. §13–14 are where it starts assuming the reader is now warmed up — which is fair, but §13.6 specifically jumps the gun on §14 vocabulary and `xlatb` at L1259 points to a section that doesn't mention it.
