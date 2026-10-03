#!/usr/bin/env python3
"""s37: host-PC -> TB index as a sorted array per code region instead of a QTree (swap-in avoidance + less heap).
FAULTREC with callchains (frG 37146601382, s12pa, CI phone-memory model): of 34k major faults on the Scudo heap in
120 s, ~31k came from the per-region QTree that maps host code addresses to TBs: tcg_region_reset_all (TB flush
destroys ~1.4M tree nodes one by one, each a cold 48-byte heap chunk) 15.9k, tcg_tb_lookup (cpu_restore_state on
guest faults walks cold nodes) 10.4k, plus Scudo's own free path. The nodes are ~67 MB of the 108 MB Scudo primary.
Within a region TBs are allocated at increasing addresses by its single owning context, so the index is an
append-only sorted array of {code ptr, tb} (16 B per TB, contiguous, binary search without touching TB headers);
the rare tcg_tb_remove (tb_gen_code lost a race and rewinds code_gen_ptr) deletes the last entry; insertion keeps
sorted order in general (memmove) for safety. A flush frees each array in one go (no per-TB walk).
Semantics unchanged: lookup returns the TB with ptr <= pc < ptr + size; foreach visits in address order and stops on
TRUE; tcg_nb_tbs sums the counts. (tb_destroy only runs qemu_spin_destroy, a no-op without TSAN.)
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
def sub(rel, old, new):
    p = root / rel; s = p.read_text()
    if s.count(old) != 1: sys.exit(f"tbarray: {rel}: anchor x{s.count(old)}: {old[:70]!r}")
    p.write_text(s.replace(old, new))
R = "tcg/region.c"
sub(R, '''struct tcg_region_tree
{
    QemuMutex lock;
    QTree*    tree;
    /* padding to avoid false sharing is computed at run-time */
};''', '''struct ivm_tbent
{
    const void*              ptr;
    struct TranslationBlock* tb;
};
struct tcg_region_tree
{
    QemuMutex          lock;
    struct ivm_tbent*  v;   /* sorted by ptr (exp/tbarray.py) */
    size_t             n, cap;
    /* padding to avoid false sharing is computed at run-time */
};
/* first index whose ptr is > p */
static size_t ivm_tb_upper(const struct tcg_region_tree* rt, const void* p)
{
    size_t lo = 0, hi = rt->n;
    while (lo < hi) {
        size_t m = lo + (hi - lo) / 2;
        if (rt->v[m].ptr > p) { hi = m; } else { lo = m + 1; }
    }
    return lo;
}''')
sub(R, '''        qemu_mutex_init(&rt->lock);
        rt->tree = q_tree_new_full(tb_tc_cmp, NULL, NULL, tb_destroy);''', '''        qemu_mutex_init(&rt->lock);
        rt->v = NULL; rt->n = rt->cap = 0;
        (void)tb_tc_cmp; (void)tb_destroy;''')
sub(R, '''    qemu_mutex_lock(&rt->lock);
    q_tree_insert(rt->tree, &tb->tc, tb);
    qemu_mutex_unlock(&rt->lock);''', '''    qemu_mutex_lock(&rt->lock);
    {
        size_t i = ivm_tb_upper(rt, tb->tc.ptr);
        if (rt->n == rt->cap) {
            rt->cap = rt->cap ? rt->cap * 2 : 4096;
            rt->v   = g_renew(struct ivm_tbent, rt->v, rt->cap);
        }
        if (i < rt->n) { memmove(&rt->v[i + 1], &rt->v[i], (rt->n - i) * sizeof(rt->v[0])); }
        rt->v[i].ptr = tb->tc.ptr;
        rt->v[i].tb  = tb;
        rt->n++;
    }
    qemu_mutex_unlock(&rt->lock);''')
sub(R, '''    qemu_mutex_lock(&rt->lock);
    q_tree_remove(rt->tree, &tb->tc);
    qemu_mutex_unlock(&rt->lock);''', '''    qemu_mutex_lock(&rt->lock);
    {
        size_t i = ivm_tb_upper(rt, tb->tc.ptr);
        while (i > 0 && rt->v[i - 1].ptr == tb->tc.ptr && rt->v[i - 1].tb != tb) { i--; }
        if (i > 0 && rt->v[i - 1].tb == tb) {
            memmove(&rt->v[i - 1], &rt->v[i], (rt->n - i) * sizeof(rt->v[0]));
            rt->n--;
        }
    }
    qemu_mutex_unlock(&rt->lock);''')
sub(R, '''    qemu_mutex_lock(&rt->lock);
    tb = q_tree_lookup(rt->tree, &s);
    qemu_mutex_unlock(&rt->lock);
    return tb;''', '''    qemu_mutex_lock(&rt->lock);
    {
        size_t i = ivm_tb_upper(rt, s.ptr);
        tb = NULL;
        if (i > 0 && ptr_cmp_tb_tc(s.ptr, &rt->v[i - 1].tb->tc) == 0) { tb = rt->v[i - 1].tb; }
    }
    qemu_mutex_unlock(&rt->lock);
    return tb;''')
sub(R, '''        q_tree_foreach(rt->tree, func, user_data);''', '''        size_t k;
        for (k = 0; k < rt->n; k++) {
            if (func((gpointer)&rt->v[k].tb->tc, rt->v[k].tb, user_data)) { break; }
        }''')
sub(R, '''        nb_tbs += q_tree_nnodes(rt->tree);''', '''        nb_tbs += rt->n;''')
sub(R, '''        /* Increment the refcount first so that destroy acts as a reset */
        q_tree_ref(rt->tree);
        q_tree_destroy(rt->tree);''', '''        /* exp/tbarray.py: drop the whole index at once (no per-TB walk over cold memory) */
        g_free(rt->v);
        rt->v = NULL; rt->n = rt->cap = 0;''')
print("tbarray: ok")
