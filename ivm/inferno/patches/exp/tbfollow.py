#!/usr/bin/env python3
"""s33 EXPERIMENT: follow forward direct branches inside a TB (superblock-lite).

Upstream ends a TB at every B / BL; the target block then starts with the exit-request poll and reloads
every guest register it needs from env, while the source block stored every dirty one. When the target
is FORWARD and on the same guest page as the TB start, we can simply continue translating at the target
inside the same TB:
  * the TB stays one contiguous range [pc_first, pc_next) (a superset of the bytes used), so TB
    invalidation on code writes / page tracking are unchanged (tb->size = pc_next - pc_first);
  * every insn still gets its own insn_start (pc), so exceptions restore the right PC;
  * forward-only => no loops inside a TB, the TB still terminates within max_insns;
  * PC-relative values use s->pc_curr (the real address), CF_PCREL tracking (pc_save) is unaffected.
Not done when single-stepping, CF_NO_GOTO_TB, or when fewer than 8 insn slots remain.
Env IVM_FOLLOW=n: max branches followed per TB (default 4, 0 = off).
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
def sub(rel, old, new):
    p = root / rel; s = p.read_text()
    if s.count(old) != 1: sys.exit(f"tbfollow: {rel}: anchor x{s.count(old)}: {old[:60]!r}")
    p.write_text(s.replace(old, new))

sub("target/arm/tcg/translate.h", "    bool is_ldex;\n", "    bool is_ldex;\n    int  ivm_follows; /* exp/tbfollow: branches followed in this TB */\n")

sub("target/arm/tcg/translate-a64.c", "static bool trans_B(DisasContext* s, arg_i* a)\n{\n    reset_btype(s);\n    gen_goto_tb(s, 0, a->imm);\n",
"""static int ivm_follow_max = -1;

/* exp/tbfollow: continue translation at a forward same-page direct branch target. */
static bool ivm_tb_follow(DisasContext* s, int64_t diff)
{
    if (unlikely(ivm_follow_max < 0)) {
        const char* e  = getenv("IVM_FOLLOW");
        ivm_follow_max = e ? atoi(e) : 4;
        if (ivm_follow_max < 0) { ivm_follow_max = 0; }
    }
    if (s->ivm_follows >= ivm_follow_max || diff <= 0 || diff >= TARGET_PAGE_SIZE || s->ss_active) { return false; }
    if (tb_cflags(s->base.tb) & CF_NO_GOTO_TB) { return false; }
    if (s->base.num_insns + 8 > s->base.max_insns) { return false; }
    if (!translator_is_same_page(&s->base, s->pc_curr + diff)) { return false; }
    s->ivm_follows++;
    s->base.pc_next = s->pc_curr + diff;
    return true;
}

static bool trans_B(DisasContext* s, arg_i* a)
{
    reset_btype(s);
    if (ivm_tb_follow(s, a->imm)) { return true; }
    gen_goto_tb(s, 0, a->imm);
""")

sub("target/arm/tcg/translate-a64.c", """    gen_pc_plus_diff(s, cpu_reg(s, 30), curr_insn_len(s));
    reset_btype(s);
    gen_goto_tb(s, 0, a->imm);
""", """    gen_pc_plus_diff(s, cpu_reg(s, 30), curr_insn_len(s));
    reset_btype(s);
    if (ivm_tb_follow(s, a->imm)) { return true; }
    gen_goto_tb(s, 0, a->imm);
""")
print("tbfollow: applied")
