#!/usr/bin/env python3
"""s33 EXPERIMENT (apply after tbfollow): continue through the FALL-THROUGH of one conditional branch per TB.

B.cond / CBZ / CBNZ / TBZ / TBNZ normally end the TB with two chained exits. Here the first such branch
in a TB becomes a side exit (inverted test -> skip label, taken edge = goto_tb slot 0) and translation
continues at pc+4 inside the same TB, so the TB stays contiguous. Exit slots are tracked per TB
(s->ivm_slots): gen_goto_tb takes the other slot when the requested one is used, and falls back to the
(inline-probed) lookup_and_goto_ptr when both are used. pc_save is restored at the skip label by the
DisasLabel mechanism (CF_PCREL correctness).
Env IVM_FOLLOWC=0 disables (default on; IVM_FOLLOW=0 does not disable this part).
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
def sub(rel, old, new):
    p = root / rel; s = p.read_text()
    if s.count(old) != 1: sys.exit(f"tbfollow2: {rel}: anchor x{s.count(old)}: {old[:60]!r}")
    p.write_text(s.replace(old, new))

A64 = "target/arm/tcg/translate-a64.c"
sub("target/arm/tcg/translate.h", "    int  ivm_follows; /* exp/tbfollow: branches followed in this TB */\n",
    "    int  ivm_follows; /* exp/tbfollow: branches followed in this TB */\n"
    "    int  ivm_slots;   /* exp/tbfollow2: goto_tb exit slots already emitted (bit n) */\n")

sub(A64, """static void gen_goto_tb(DisasContext* s, int n, int64_t diff)
{
    if (use_goto_tb(s, s->pc_curr + diff)) {
""", """static void gen_goto_tb(DisasContext* s, int n, int64_t diff)
{
    if (s->ivm_slots & (1 << n)) { n ^= 1; } /* exp/tbfollow2: a side exit took this slot */
    if (!(s->ivm_slots & (1 << n)) && use_goto_tb(s, s->pc_curr + diff)) {
        s->ivm_slots |= 1 << n;
""")

sub(A64, "static bool trans_B(DisasContext* s, arg_i* a)\n{\n    reset_btype(s);\n    if (ivm_tb_follow(s, a->imm)) { return true; }\n",
"""static int ivm_followc = -1;

/* exp/tbfollow2: may this conditional branch become a side exit (translation continues at pc+4)? */
static bool ivm_cond_follow_ok(DisasContext* s)
{
    if (unlikely(ivm_followc < 0)) {
        const char* e = getenv("IVM_FOLLOWC");
        ivm_followc   = e ? (atoi(e) != 0) : 1;
    }
    if (!ivm_followc || s->ivm_slots != 0 || s->ss_active) { return false; }
    if (tb_cflags(s->base.tb) & CF_NO_GOTO_TB) { return false; }
    if (s->base.num_insns + 8 > s->base.max_insns) { return false; }
    return true;
}

/* exp/tbfollow2: after the inverted test branched to skip: emit the taken exit, then resume at pc+4 */
static void ivm_cond_side_exit(DisasContext* s, DisasLabel skip, int64_t diff)
{
    gen_goto_tb(s, 0, diff);
    set_disas_label(s, skip);
    s->base.is_jmp = DISAS_NEXT;
}

static bool trans_B(DisasContext* s, arg_i* a)
{
    reset_btype(s);
    if (ivm_tb_follow(s, a->imm)) { return true; }
""")

sub(A64, """    tcg_cmp = read_cpu_reg(s, a->rt, a->sf);
    reset_btype(s);

    match = gen_disas_label(s);
""", """    tcg_cmp = read_cpu_reg(s, a->rt, a->sf);
    reset_btype(s);

    if (ivm_cond_follow_ok(s)) {
        DisasLabel skip = gen_disas_label(s);
        tcg_gen_brcondi_i64(a->nz ? TCG_COND_EQ : TCG_COND_NE, tcg_cmp, 0, skip.label);
        ivm_cond_side_exit(s, skip, a->imm);
        return true;
    }

    match = gen_disas_label(s);
""")

sub(A64, """    tcg_gen_andi_i64(tcg_cmp, cpu_reg(s, a->rt), 1ULL << a->bitpos);

    reset_btype(s);

    match = gen_disas_label(s);
""", """    tcg_gen_andi_i64(tcg_cmp, cpu_reg(s, a->rt), 1ULL << a->bitpos);

    reset_btype(s);

    if (ivm_cond_follow_ok(s)) {
        DisasLabel skip = gen_disas_label(s);
        tcg_gen_brcondi_i64(a->nz ? TCG_COND_EQ : TCG_COND_NE, tcg_cmp, 0, skip.label);
        ivm_cond_side_exit(s, skip, a->imm);
        return true;
    }

    match = gen_disas_label(s);
""")

sub(A64, """    if (a->cond < 0x0e) {
        /* genuinely conditional branches */
        DisasLabel match = gen_disas_label(s);
""", """    if (a->cond < 0x0e && ivm_cond_follow_ok(s)) {
        DisasLabel skip = gen_disas_label(s);
        arm_gen_test_cc(a->cond ^ 1, skip.label);
        ivm_cond_side_exit(s, skip, a->imm);
    }
    else if (a->cond < 0x0e) {
        /* genuinely conditional branches */
        DisasLabel match = gen_disas_label(s);
""")
print("tbfollow2: applied")
