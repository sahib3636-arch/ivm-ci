#!/usr/bin/env python3
"""s33 EXPERIMENT (apply after tbfollow): also follow forward B/BL whose target is on the NEXT guest page.

Upstream may not chain (goto_tb) to another page, so such a branch ends in update-pc + jump-cache lookup.
Generic TCG supports TBs spanning two pages: translator_ld maps the second page and records
tb->page_addr[1] (TB invalidation on writes to either page), tb_lookup_cmp re-checks the second page's
mapping on every qht lookup, and TLB page flushes clear jump-cache entries of TBs that start on the
previous page. A forward jump into page+1 keeps the TB one contiguous range inside those two pages.
A64 itself never crosses pages, because a fetch fault on the second page during translation would be
raised with the wrong PC. So the target page is probed first, non-faulting: it must be mapped
executable for the current regime, normal RAM (no MMIO / watchpoint flags) and a full TARGET_PAGE
mapping (same test as get_page_addr_code_hostp). max_insns is re-bounded to the second page's end.
CF_PCREL restore: upstream records pc & ~PAGE_MASK and restores (env->pc & PAGE_MASK) | off, which assumes
the faulting insn is on the page of the value in cpu_pc. Insn_start now records pc - (pc_save & PAGE_MASK)
(pc_save = translation-time value of cpu_pc) and restore adds it: identical for single-page TBs
(off < page), correct for page-2 insns.
Env IVM_FOLLOWX=0 restricts tbfollow to the first page again (default on).
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
p = root / "target/arm/tcg/translate-a64.c"; s = p.read_text()

old = "    if (!translator_is_same_page(&s->base, s->pc_curr + diff)) { return false; }\n"
new = """    if (!translator_is_same_page(&s->base, s->pc_curr + diff) && !ivm_follow_next_page_ok(s, s->pc_curr + diff)) {
        return false;
    }
"""
if s.count(old) != 1: sys.exit("tbfollow3: anchor 1")
s = s.replace(old, new)

old2 = "/* exp/tbfollow: continue translation at a forward same-page direct branch target. */"
new2 = """#include "accel/tcg/probe.h"
#include "exec/tlb-flags.h"

/* exp/tbfollow3: may a followed branch enter the page right after the TB's first page? */
static bool ivm_follow_next_page_ok(DisasContext* s, vaddr dest)
{
    static int ivm_followx = -1;
    vaddr      first       = s->base.pc_first & TARGET_PAGE_MASK;
    void*      host        = NULL;
    CPUTLBEntryFull* full  = NULL;
    int        flags;

    if (unlikely(ivm_followx < 0)) {
        const char* e = getenv("IVM_FOLLOWX");
        ivm_followx   = e ? (atoi(e) != 0) : 1;
    }
    if (!ivm_followx || current_cpu == NULL) { return false; }
    /* still on the first page (no earlier jump went to page 2), target inside page 2 */
    if ((s->pc_curr & TARGET_PAGE_MASK) != first) { return false; }
    if ((dest & TARGET_PAGE_MASK) != first + TARGET_PAGE_SIZE) { return false; }
    if (tb_page_addr0(s->base.tb) == -1) { return false; }
    flags = probe_access_full(cpu_env(current_cpu), dest, 0, MMU_INST_FETCH, s->base.code_mmuidx, true, &host, &full, 0);
    if (flags & (TLB_INVALID_MASK | TLB_MMIO | TLB_WATCHPOINT)) { return false; }
    if (host == NULL || full == NULL || full->lg_page_size < TARGET_PAGE_BITS) { return false; }
    return true;
}

/* exp/tbfollow: continue translation at a forward same-page direct branch target. */"""
if s.count(old2) != 1: sys.exit("tbfollow3: anchor 2")
s = s.replace(old2, new2)
old3 = """    if (tb_cflags(dcbase->tb) & CF_PCREL) { pc_arg &= ~TARGET_PAGE_MASK; }
    tcg_gen_insn_start(pc_arg, 0, 0);"""
new3 = """    if (tb_cflags(dcbase->tb) & CF_PCREL) {
        /* exp/tbfollow3: relative to the page of cpu_pc's known value (pc_save), restore adds it */
        if (dc->pc_save != -1) { pc_arg -= dc->pc_save & TARGET_PAGE_MASK; }
        else { pc_arg &= ~TARGET_PAGE_MASK; } /* upstream encoding (cpu_pc unknown: never on page 2) */
    }
    tcg_gen_insn_start(pc_arg, 0, 0);"""
if s.count(old3) != 1: sys.exit("tbfollow3: anchor 3")
s = s.replace(old3, new3)
p.write_text(s)

c = root / "target/arm/cpu.c"; t = c.read_text()
old4 = "        if (tb_cflags(tb) & CF_PCREL) { env->pc = (env->pc & TARGET_PAGE_MASK) | data[0]; }"
new4 = "        if (tb_cflags(tb) & CF_PCREL) { env->pc = (env->pc & TARGET_PAGE_MASK) + data[0]; } /* exp/tbfollow3 */"
if t.count(old4) != 1: sys.exit("tbfollow3: anchor 4")
c.write_text(t.replace(old4, new4))
print("tbfollow3: applied")
