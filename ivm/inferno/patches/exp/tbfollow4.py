#!/usr/bin/env python3
"""s33 EXPERIMENT (apply after tbfollow, tbfollow2, tbfollow3): guarded RET follow ("inline" small callees).

When tbfollow followed a BL inside this TB, the expected return address (BL + 4) is pushed on a small
per-TB stack. A later `RET Xn` in the same TB pops it and emits a runtime guard instead of ending the TB:
    if (Xn != expected) { pc = Xn; jump-cache lookup }   // exact upstream RET semantics
    else                continue translating at expected
The expected value is materialised PC-relative (gen_pc_plus_diff), so CF_PCREL TBs stay position
independent; pc_save is restored on the fall-through path by the DisasLabel mechanism.
Jumping back to BL+4 makes the translated range non-monotonic, so the TB size now comes from the highest
insn end seen (DisasContextBase.ivm_pc_hi) instead of the final pc_next; TB invalidation therefore still
covers every byte used. Each RET follow counts against IVM_FOLLOW (max follows per TB).
Env IVM_FOLLOWR=0 disables (default on).
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
def sub(rel, old, new):
    p = root / rel; s = p.read_text()
    if s.count(old) != 1: sys.exit(f"tbfollow4: {rel}: anchor x{s.count(old)}: {old[:60]!r}")
    p.write_text(s.replace(old, new))

# 1. highest insn end per translation (generic)
sub("include/exec/translator.h", "    uint8_t           code_mmuidx;\n",
    "    uint8_t           code_mmuidx;\n    vaddr             ivm_pc_hi; /* exp/tbfollow4: highest insn end translated (0 = unused) */\n")
sub("accel/tcg/translator.c", "    db->code_mmuidx  = cpu_mmu_index(cpu, true);\n",
    "    db->code_mmuidx  = cpu_mmu_index(cpu, true);\n    db->ivm_pc_hi    = 0;\n")
sub("accel/tcg/translator.c", "    tb->size   = db->pc_next - db->pc_first;\n",
    "    tb->size   = MAX(db->pc_next, db->ivm_pc_hi) - db->pc_first; /* exp/tbfollow4 */\n")

A64 = "target/arm/tcg/translate-a64.c"
# record the end of the straight-line run before every pc_next redirect (HLEs may advance pc_next by many insns)
sub(A64, "    s->base.pc_next = s->pc_curr + diff;\n",
    "    if (s->base.pc_next > s->base.ivm_pc_hi) { s->base.ivm_pc_hi = s->base.pc_next; } /* exp/tbfollow4 */\n"
    "    s->base.pc_next = s->pc_curr + diff;\n")

sub("target/arm/tcg/translate.h", "    int  ivm_slots;   /* exp/tbfollow2: goto_tb exit slots already emitted (bit n) */\n",
    "    int  ivm_slots;   /* exp/tbfollow2: goto_tb exit slots already emitted (bit n) */\n"
    "    int  ivm_ret_n;   /* exp/tbfollow4: expected return addresses of followed BLs */\n"
    "    uint64_t ivm_ret[4];\n")

# 2. push at a followed BL
sub(A64, """    gen_pc_plus_diff(s, cpu_reg(s, 30), curr_insn_len(s));
    reset_btype(s);
    if (ivm_tb_follow(s, a->imm)) { return true; }
""", """    gen_pc_plus_diff(s, cpu_reg(s, 30), curr_insn_len(s));
    reset_btype(s);
    if (ivm_tb_follow(s, a->imm)) {
        /* exp/tbfollow4: remember the return address (s->pc_curr is still the BL) */
        if (s->ivm_ret_n < 4) { s->ivm_ret[s->ivm_ret_n++] = s->pc_curr + 4; }
        else { memmove(s->ivm_ret, s->ivm_ret + 1, 3 * sizeof(s->ivm_ret[0])); s->ivm_ret[3] = s->pc_curr + 4; }
        return true;
    }
""")

# 3. guarded RET
sub(A64, """static bool trans_RET(DisasContext* s, arg_r* a)
{
    gen_a64_set_pc(s, cpu_reg(s, a->rn));
""", """static int ivm_followr = -1;

/* exp/tbfollow4: guarded continuation at the return address of a BL followed in this TB */
static bool ivm_ret_follow(DisasContext* s, int rn)
{
    uint64_t   expect;
    TCGv_i64   exp, dst;
    DisasLabel ok;

    if (unlikely(ivm_followr < 0)) {
        const char* e = getenv("IVM_FOLLOWR");
        ivm_followr   = e ? (atoi(e) != 0) : 1;
    }
    if (!ivm_followr || s->ivm_ret_n == 0 || s->ss_active) { return false; }
    if (s->ivm_follows >= ivm_follow_max || s->pc_save == -1) { return false; }
    if (tb_cflags(s->base.tb) & CF_NO_GOTO_TB) { return false; }
    if (s->base.num_insns + 8 > s->base.max_insns) { return false; }
    expect = s->ivm_ret[s->ivm_ret_n - 1];
    /* the return address must be on a page this TB already translates from */
    if (!translator_is_same_page(&s->base, expect) && ((expect ^ s->pc_curr) & TARGET_PAGE_MASK) != 0) { return false; }
    s->ivm_ret_n--;
    s->ivm_follows++;

    dst = cpu_reg(s, rn);
    exp = tcg_temp_new_i64();
    gen_pc_plus_diff(s, exp, expect - s->pc_curr);
    ok = gen_disas_label(s);
    tcg_gen_brcond_i64(TCG_COND_EQ, dst, exp, ok.label);
    /* mismatch: exactly the upstream RET exit */
    gen_a64_set_pc(s, dst);
    ivm_gen_lookup_and_goto_ptr(s);
    set_disas_label(s, ok);
    s->base.is_jmp  = DISAS_NEXT;
    if (s->base.pc_next > s->base.ivm_pc_hi) { s->base.ivm_pc_hi = s->base.pc_next; }
    s->base.pc_next = expect;
    ivm_follow_bound(s);
    return true;
}

static bool trans_RET(DisasContext* s, arg_r* a)
{
    if (ivm_ret_follow(s, a->rn)) { return true; }
    gen_a64_set_pc(s, cpu_reg(s, a->rn));
""")
print("tbfollow4: applied")
