#!/usr/bin/env python3
"""s34 tbevict: partial code-cache eviction instead of a full tb_flush when the JIT buffer fills.

Evidence (s34 app-launch bench, dev-s11pm perf, NOTES): with tb-size 512 MB the buffer filled 11 times in one
~400 s bench run (boot + swipes + 16 app launches; 844k live TBs, 485 MB used). Every fill was a full tb_flush: all
translations of kernel + SpringBoard + backboardd + the app are thrown away at once and every vCPU retranslates
its whole hot set (stutter burst; translation 3.5 % of app-phase host time vs 0.3 % in swipes).

With IVM_TBEVICT=1 (default 1; =0 restores upstream behaviour) a full buffer evicts only the OLDEST ~1/4 of the
code regions (FIFO by allocation order; regions that a TCG context is currently filling are never evicted):
  every live TB in those regions is invalidated exactly like do_tb_phys_invalidate (CF_INVALID, qht remove, page
  list remove, unchain both outgoing jumps, unlink all incoming jumps) but the per-TB jump-cache flush (which
  for CF_PCREL TBs clears every vCPU's whole jc per TB) is replaced by ONE jc flush per vCPU at the end. The
  regions' tb trees are reset and the regions go on a free list that tcg_region_alloc uses once the never-used
  regions are exhausted. Runs in the same exclusive (all vCPUs stopped) context as tb_flush. IVM_TBEVICT_DIV=n
  evicts n_regions/n per event (default 4). Falls back to a full tb_flush if nothing can be evicted.
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])

def sub(rel, old, new, count=1):
    p = root / rel; s = p.read_text(); n = s.count(old)
    if n != count: sys.exit(f"tbevict: {rel}: expected {count}, found {n}: {old[:80]!r}")
    p.write_text(s.replace(old, new))

R = "tcg/region.c"
sub(R, "static struct tcg_region_state region;\n",
    "static struct tcg_region_state region;\n\n"
    "/* ivm tbevict: per-region allocation sequence + free list (regions reclaimed by ivm_tb_evict) */\n"
    "#define IVM_EV_MAXR 1024\n"
    "static uint64_t ivm_rseq[IVM_EV_MAXR];\n"
    "static uint8_t  ivm_rfree[IVM_EV_MAXR];\n"
    "static uint64_t ivm_rseq_next;\n"
    "static size_t   ivm_nfree;\n")
sub(R, """static bool tcg_region_alloc__locked(TCGContext* s)
{
    if (region.current == region.n) { return true; }
    tcg_region_assign(s, region.current);
    region.current++;
    return false;
}""", """static bool tcg_region_alloc__locked(TCGContext* s)
{
    if (region.current == region.n) {
        if (ivm_nfree) {
            for (size_t i = 0; i < region.n && i < IVM_EV_MAXR; i++) {
                if (ivm_rfree[i]) {
                    ivm_rfree[i] = 0;
                    ivm_nfree--;
                    ivm_rseq[i] = ++ivm_rseq_next;
                    tcg_region_assign(s, i);
                    return false;
                }
            }
        }
        return true;
    }
    if (region.current < IVM_EV_MAXR) { ivm_rseq[region.current] = ++ivm_rseq_next; }
    tcg_region_assign(s, region.current);
    region.current++;
    return false;
}

static size_t ivm_region_idx(const void* p)
{
    if (p < region.start_aligned) { return 0; }
    size_t off = (size_t)(p - region.start_aligned);
    if (off > region.stride * (region.n - 1)) { return region.n - 1; }
    return off / region.stride;
}

/*
 * ivm tbevict (exclusive context): choose up to @max oldest full regions not in use by any TCG context.
 * Returns SIZE_MAX if there is free space already (another vCPU's flush/evict got there first).
 */
size_t tcg_region_ivm_pick(size_t* victims, size_t max);
size_t tcg_region_ivm_pick(size_t* victims, size_t max)
{
    uint8_t  inuse[IVM_EV_MAXR] = {0};
    size_t   nv = 0;
    unsigned n_ctxs = qatomic_read(&tcg_cur_ctxs);

    if (region.n > IVM_EV_MAXR) { return 0; }
    qemu_mutex_lock(&region.lock);
    if (region.current < region.n || ivm_nfree) {
        qemu_mutex_unlock(&region.lock);
        return SIZE_MAX;
    }
    for (unsigned i = 0; i < n_ctxs; i++) {
        TCGContext* s = qatomic_read(&tcg_ctxs[i]);
        if (s && s->code_gen_buffer) { inuse[ivm_region_idx(s->code_gen_buffer)] = 1; }
    }
    while (nv < max) {
        size_t best = SIZE_MAX;
        for (size_t i = 0; i < region.n; i++) {
            if (inuse[i] || ivm_rfree[i]) { continue; }
            if (best == SIZE_MAX || ivm_rseq[i] < ivm_rseq[best]) { best = i; }
        }
        if (best == SIZE_MAX) { break; }
        inuse[best]    = 1;
        victims[nv++]  = best;
    }
    qemu_mutex_unlock(&region.lock);
    return nv;
}

void tcg_region_ivm_foreach(size_t idx, GTraverseFunc func, gpointer user_data);
void tcg_region_ivm_foreach(size_t idx, GTraverseFunc func, gpointer user_data)
{
    struct tcg_region_tree* rt = region_trees + idx * tree_size;

    qemu_mutex_lock(&rt->lock);
    q_tree_foreach(rt->tree, func, user_data);
    qemu_mutex_unlock(&rt->lock);
}

void tcg_region_ivm_release(size_t idx);
void tcg_region_ivm_release(size_t idx)
{
    struct tcg_region_tree* rt = region_trees + idx * tree_size;
    void *start, *end;
    size_t sz;

    qemu_mutex_lock(&rt->lock);
    q_tree_ref(rt->tree);
    q_tree_destroy(rt->tree);
    qemu_mutex_unlock(&rt->lock);

    tcg_region_bounds(idx, &start, &end);
    sz = (size_t)(end - start);
    sz = sz > TCG_HIGHWATER ? sz - TCG_HIGHWATER : 0;
    qemu_mutex_lock(&region.lock);
    region.agg_size_full = region.agg_size_full > sz ? region.agg_size_full - sz : 0;
    if (!ivm_rfree[idx]) { ivm_rfree[idx] = 1; ivm_nfree++; }
    qemu_mutex_unlock(&region.lock);
}""")
sub(R, """    qemu_mutex_lock(&region.lock);
    region.current       = 0;
    region.agg_size_full = 0;
""", """    qemu_mutex_lock(&region.lock);
    region.current       = 0;
    region.agg_size_full = 0;
    memset(ivm_rfree, 0, sizeof(ivm_rfree));
    ivm_nfree = 0;
""")

T = "accel/tcg/tb-maint.c"
sub(T, "static void tb_phys_invalidate__locked(TranslationBlock* tb)\n{",
    """/* ---- ivm tbevict (see ivm/inferno/patches/exp/tbevict.py) ---- */
size_t   tcg_region_ivm_pick(size_t* victims, size_t max);
void     tcg_region_ivm_foreach(size_t idx, GTraverseFunc func, gpointer user_data);
void     tcg_region_ivm_release(size_t idx);
unsigned ivm_tb_evict_count;
uint64_t ivm_tb_evicted;

int ivm_tbevict_on(void)
{
    static int v = -1;
    if (unlikely(v < 0)) {
        const char* e = getenv("IVM_TBEVICT");
        v = (e && *e) ? atoi(e) != 0 : 1;
    }
    return v;
}

static gboolean ivm_evict_one(gpointer key, gpointer value, gpointer data)
{
    TranslationBlock* tb   = value;
    uint32_t          orig = tb_cflags(tb);
    tb_page_addr_t    phys_pc;
    uint32_t          h;

    if (orig & CF_INVALID) { return FALSE; } /* already invalidated (page write): unlinked back then */
    qemu_spin_lock(&tb->jmp_lock);
    qatomic_set(&tb->cflags, orig | CF_INVALID);
    qemu_spin_unlock(&tb->jmp_lock);
    phys_pc = tb_page_addr0(tb);
    h       = tb_hash_func(phys_pc, (orig & CF_PCREL ? 0 : tb->pc), tb->flags, tb->cs_base, orig);
    if (!qht_remove(&tb_ctx.htable, tb, h)) { return FALSE; }
    if (phys_pc != -1) { tb_remove(tb); }
    tb_remove_from_jmp_list(tb, 0);
    tb_remove_from_jmp_list(tb, 1);
    tb_jmp_unlink(tb);
    (*(size_t*)data)++;
    return FALSE;
}

/* Must be called from a context in which no cpus are running (same as tb_flush__exclusive_or_serial). */
void ivm_tb_evict__exclusive_or_serial(void)
{
    static int div = 0;
    size_t     v[IVM_EV_MAX], nv, cnt = 0, want;
    CPUState*  cpu;

    if (!div) {
        const char* e = getenv("IVM_TBEVICT_DIV");
        div = (e && atoi(e) > 0) ? atoi(e) : 4;
    }
    want = tcg_nb_regions_ivm() / div;
    if (want < 1) { want = 1; }
    if (want > IVM_EV_MAX) { want = IVM_EV_MAX; }
    nv = tcg_region_ivm_pick(v, want);
    if (nv == SIZE_MAX) { return; } /* space already available */
    if (nv == 0) {
        tb_flush__exclusive_or_serial();
        return;
    }
    int64_t t0 = get_clock_realtime();
    qemu_thread_jit_write();
    for (size_t i = 0; i < nv; i++) { tcg_region_ivm_foreach(v[i], ivm_evict_one, &cnt); }
    qemu_thread_jit_execute();
    CPU_FOREACH (cpu) { tcg_flush_jmp_cache(cpu); }
    for (size_t i = 0; i < nv; i++) { tcg_region_ivm_release(v[i]); }
    qatomic_set(&tb_ctx.tb_phys_invalidate_count, tb_ctx.tb_phys_invalidate_count + cnt);
    ivm_tb_evicted += cnt;
    qatomic_inc(&ivm_tb_evict_count);
    fprintf(stderr, "ivm tbevict #%u: %zu regions, %zu TBs, %.1f ms\n", ivm_tb_evict_count, nv, cnt,
            (get_clock_realtime() - t0) / 1e6);
}

static void do_ivm_tb_evict(CPUState* cpu, run_on_cpu_data unused)
{
    ivm_tb_evict__exclusive_or_serial();
}

void queue_ivm_tb_evict(CPUState* cs)
{
    async_safe_run_on_cpu(cs, do_ivm_tb_evict, RUN_ON_CPU_NULL);
}

static void tb_phys_invalidate__locked(TranslationBlock* tb)
{""")
sub(T, "/* ---- ivm tbevict (see", "#define IVM_EV_MAX 256\nsize_t tcg_nb_regions_ivm(void);\n/* ---- ivm tbevict (see")
sub(R, "size_t tcg_region_ivm_pick(size_t* victims, size_t max);\nsize_t tcg_region_ivm_pick(",
    "size_t tcg_nb_regions_ivm(void);\nsize_t tcg_nb_regions_ivm(void) { return region.n; }\n\n"
    "size_t tcg_region_ivm_pick(size_t* victims, size_t max);\nsize_t tcg_region_ivm_pick(")

sub(T, '#include "system/runstate.h"\n', '#include "system/runstate.h"\n#include "qemu/timer.h"\n')
sub(T, """    CPU_FOREACH (cpu) { tcg_flush_jmp_cache(cpu); }

    qht_reset_size(&tb_ctx.htable, CODE_GEN_HTABLE_SIZE);
    tb_remove_all();

    tcg_region_reset_all();
""", """    int64_t ivm_t0 = get_clock_realtime();
    CPU_FOREACH (cpu) { tcg_flush_jmp_cache(cpu); }

    qht_reset_size(&tb_ctx.htable, CODE_GEN_HTABLE_SIZE);
    tb_remove_all();

    tcg_region_reset_all();
    fprintf(stderr, "ivm tb_flush #%u: %.1f ms\\n", tb_ctx.tb_flush_count + 1, (get_clock_realtime() - ivm_t0) / 1e6);
""")

H = "include/exec/tb-flush.h"
sub(H, "void queue_tb_flush(CPUState* cs);\n",
    "void queue_tb_flush(CPUState* cs);\n\n"
    "/* ivm tbevict: evict the oldest code regions instead of flushing everything (IVM_TBEVICT, default on) */\n"
    "int  ivm_tbevict_on(void);\n"
    "void ivm_tb_evict__exclusive_or_serial(void);\n"
    "void queue_ivm_tb_evict(CPUState* cs);\n"
    "extern unsigned ivm_tb_evict_count;\n"
    "extern uint64_t ivm_tb_evicted;\n")

X = "accel/tcg/translate-all.c"
sub(X, """        if (cpu_in_serial_context(cpu)) {
            tb_flush__exclusive_or_serial();
            goto buffer_overflow;
        }
        queue_tb_flush(cpu);
""", """        if (cpu_in_serial_context(cpu)) {
            if (ivm_tbevict_on()) { ivm_tb_evict__exclusive_or_serial(); }
            else { tb_flush__exclusive_or_serial(); }
            goto buffer_overflow;
        }
        if (ivm_tbevict_on()) { queue_ivm_tb_evict(cpu); }
        else { queue_tb_flush(cpu); }
""")

S = "accel/tcg/tcg-stats.c"
sub(S, """    g_string_append_printf(buf, "TB flush count      %u\\n", qatomic_read(&tb_ctx.tb_flush_count));\n""",
    """    g_string_append_printf(buf, "TB flush count      %u\\n", qatomic_read(&tb_ctx.tb_flush_count));\n"""
    """    g_string_append_printf(buf, "TB evict count      %u (%" PRIu64 " TBs, IVM_TBEVICT=%d)\\n", qatomic_read(&ivm_tb_evict_count), ivm_tb_evicted, ivm_tbevict_on());\n""")
sub(S, '#include "tb-context.h"\n', '#include "tb-context.h"\n#include "exec/tb-flush.h"\n')
print("tbevict: applied")
