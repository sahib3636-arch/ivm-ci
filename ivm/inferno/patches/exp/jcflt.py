#!/usr/bin/env python3
"""s35 jcflt: stop TLB maintenance from wiping unrelated jump-cache entries (more jc hits, fewer qht lookups).

Evidence: in the s34 app-launch profile qht_lookup_custom is the top engine function (5.6-5.8 %), + tb_lookup_cmp
1.3 %, tb_lookup 0.9 %, get_page_addr_code 0.9 % => ~8.7 % of host time is jc-miss handling.  s27 jclog: 9.5M
page-bucket clears per bench run.

1. IVM_JCPAGE (default 1): tb_jmp_cache_clear_page() clears the whole 128-entry hash bucket range of a page
   (TB_JMP_PAGE_SIZE = 2^(14/2)) although other pages share that range; most TLBI'd pages are data pages with no
   TBs at all.  Now only entries whose pc lies in that page lose their TB (same per-page semantics: callers still
   clear page-1 too for TBs spilling into the flushed page).  The entry pc is written only by the owning vCPU and
   clears run on it (assert_cpu_is_self), so reading pc is race-free.
2. IVM_TLBASID (default 1): TLBI ASIDE1{,IS,OS} was a FULL flush of every EL1&0 TLB entry and the whole jc on
   every vCPU (QEMU ignores the ASID).  Architecturally it only removes non-global (nG) entries, so it now uses
   Inferno's tlb_flush_asid_tagged_by_mmuidx (drops only asid-tagged entries: a superset of that ASID) on all
   vCPUs (synced like tlb_flush_by_mmuidx_all_cpus_synced), and the jc flush that accompanies an asid-tagged TLB
   flush only clears user-half entries (VA[55]==0): global (kernel) translations did not change.
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])

def sub(rel, old, new, count=1):
    p = root / rel; s = p.read_text(); n = s.count(old)
    if n != count: sys.exit(f"jcflt: {rel}: expected {count}, found {n}: {old[:80]!r}")
    p.write_text(s.replace(old, new))

C = "accel/tcg/cputlb.c"
sub(C, """static void tb_jmp_cache_clear_page(CPUState* cpu, vaddr page_addr)
{
    CPUJumpCache* jc = cpu->tb_jmp_cache;
    int           i, i0;

    if (unlikely(!jc)) { return; }

    i0 = tb_jmp_cache_hash_page(page_addr);
    for (i = 0; i < TB_JMP_PAGE_SIZE; i++) { qatomic_set(&jc->array[i0 + i].tb, NULL); }
}""", """int ivm_jcpage = -1, ivm_tlbasid = -1;

static inline int ivm_env_flag(int* v, const char* name)
{
    if (unlikely(*v < 0)) {
        const char* e = getenv(name);
        *v = (e && *e) ? atoi(e) != 0 : 1;
    }
    return *v;
}

static void tb_jmp_cache_clear_page(CPUState* cpu, vaddr page_addr)
{
    CPUJumpCache* jc = cpu->tb_jmp_cache;
    int           i, i0;

    if (unlikely(!jc)) { return; }

    i0 = tb_jmp_cache_hash_page(page_addr);
    if (likely(ivm_env_flag(&ivm_jcpage, "IVM_JCPAGE"))) {
        /* ivm jcflt: only entries of THIS page (the bucket range is shared with other pages) */
        vaddr pg = page_addr & TARGET_PAGE_MASK;
        for (i = 0; i < TB_JMP_PAGE_SIZE; i++) {
            if ((jc->array[i0 + i].pc & TARGET_PAGE_MASK) == pg) { qatomic_set(&jc->array[i0 + i].tb, NULL); }
        }
        return;
    }
    for (i = 0; i < TB_JMP_PAGE_SIZE; i++) { qatomic_set(&jc->array[i0 + i].tb, NULL); }
}

/* ivm jcflt: user-half (VA[55]==0) jc entries only — after a flush of non-global TLB entries */
static void ivm_flush_jmp_cache_user(CPUState* cpu)
{
    CPUJumpCache* jc = cpu->tb_jmp_cache;

    if (unlikely(!jc)) { return; }
    for (int i = 0; i < TB_JMP_CACHE_SIZE; i++) {
        if (!((jc->array[i].pc >> 55) & 1)) { qatomic_set(&jc->array[i].tb, NULL); }
    }
}""")
sub(C, """    for (work = todo; work != 0; work &= work - 1) { tlb_flush_asid_tagged_locked(cpu, ctz32(work)); }

    qemu_spin_unlock(&cpu->neg.tlb.c.lock);

    if (todo != 0) { tcg_flush_jmp_cache(cpu); }
}""", """    for (work = todo; work != 0; work &= work - 1) { tlb_flush_asid_tagged_locked(cpu, ctz32(work)); }

    qemu_spin_unlock(&cpu->neg.tlb.c.lock);

    if (todo != 0) {
        if (ivm_env_flag(&ivm_tlbasid, "IVM_TLBASID")) { ivm_flush_jmp_cache_user(cpu); }
        else { tcg_flush_jmp_cache(cpu); }
    }
}

static void ivm_asid_flush_work(CPUState* cpu, run_on_cpu_data d) { tlb_flush_asid_tagged_by_mmuidx(cpu, d.host_int); }

/* ivm jcflt: TLBI ASIDE1IS — drop non-global entries on every vCPU (synced), keep global (kernel) ones */
void ivm_tlb_flush_asid_all_cpus_synced(CPUState* src_cpu, MMUIdxMap idxmap, bool all);
void ivm_tlb_flush_asid_all_cpus_synced(CPUState* src_cpu, MMUIdxMap idxmap, bool all)
{
    const run_on_cpu_data d = RUN_ON_CPU_HOST_INT(idxmap);
    CPUState*             cpu;

    if (!ivm_env_flag(&ivm_tlbasid, "IVM_TLBASID")) {
        if (all) { tlb_flush_by_mmuidx_all_cpus_synced(src_cpu, idxmap); }
        else { tlb_flush_by_mmuidx(src_cpu, idxmap); }
        return;
    }
    if (!all) {
        if (qemu_cpu_is_self(src_cpu)) { tlb_flush_asid_tagged_by_mmuidx(src_cpu, idxmap); }
        else { async_run_on_cpu(src_cpu, ivm_asid_flush_work, d); }
        return;
    }
    CPU_FOREACH (cpu) {
        if (cpu != src_cpu) { async_run_on_cpu(cpu, ivm_asid_flush_work, d); }
    }
    async_safe_run_on_cpu(src_cpu, ivm_asid_flush_work, d);
}""")

T = "target/arm/tcg/tlb-insns.c"
sub(T, """static void tlbi_aa64_vmalle1_write(CPUARMState* env, const ARMCPRegInfo* ri, uint64_t value)
{""", """void ivm_tlb_flush_asid_all_cpus_synced(CPUState* src_cpu, MMUIdxMap idxmap, bool all);

/* ivm jcflt: TLBI ASIDE1{IS,OS} / ASIDE1 only remove non-global entries */
static void tlbi_aa64_aside1is_write(CPUARMState* env, const ARMCPRegInfo* ri, uint64_t value)
{
    ivm_tlb_flush_asid_all_cpus_synced(env_cpu(env), vae1_tlbmask(env), true);
}

static void tlbi_aa64_aside1_write(CPUARMState* env, const ARMCPRegInfo* ri, uint64_t value)
{
    ivm_tlb_flush_asid_all_cpus_synced(env_cpu(env), vae1_tlbmask(env), tlb_force_broadcast(env));
}

static void tlbi_aa64_vmalle1_write(CPUARMState* env, const ARMCPRegInfo* ri, uint64_t value)
{""")
# rewire the three ASIDE1 regs (IS, local, OS): their writefn follows the .fgt line
sub(T, """     .fgt      = FGT_TLBIASIDE1IS,
     .writefn  = tlbi_aa64_vmalle1is_write},""", """     .fgt      = FGT_TLBIASIDE1IS,
     .writefn  = tlbi_aa64_aside1is_write},""")
sub(T, """     .fgt      = FGT_TLBIASIDE1,
     .writefn  = tlbi_aa64_vmalle1_write},""", """     .fgt      = FGT_TLBIASIDE1,
     .writefn  = tlbi_aa64_aside1_write},""")
sub(T, """     .fgt      = FGT_TLBIASIDE1OS,
     .writefn  = tlbi_aa64_vmalle1is_write},""", """     .fgt      = FGT_TLBIASIDE1OS,
     .writefn  = tlbi_aa64_aside1is_write},""")
print("jcflt: applied")
