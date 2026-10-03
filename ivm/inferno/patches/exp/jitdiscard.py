#!/usr/bin/env python3
"""s37: drop stale JIT code pages before reusing a code-cache region (swap-in avoidance).
After a TB flush the code buffer (tb-size 1024 MB) is refilled from the start. The region about to be written was last
written minutes ago, so under memory pressure Android has already swapped it to zram -> every first store of new code
into it is a major fault (zram read of dead code). Now, when a region is (re)assigned to a TCG context after a flush,
its pages are discarded first (MADV_DONTNEED on the private anonymous buffer -> fresh zero pages = minor faults), and
RSS drops by the stale part of the cache right away (less pressure on the guest RAM).
Only before the first write into a recycled region, outside the JIT hot path, under region.lock. Skipped for split-wx
(memfd) buffers. Env IVM_JITDISCARD=0 disables.
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
def sub(rel, old, new):
    p = root / rel; s = p.read_text()
    if s.count(old) != 1: sys.exit(f"jitdiscard: {rel}: anchor x{s.count(old)}: {old[:70]!r}")
    p.write_text(s.replace(old, new))
R = "tcg/region.c"
sub(R, '''static void tcg_region_assign(TCGContext* s, size_t curr_region)
{
    void *start, *end;

    tcg_region_bounds(curr_region, &start, &end);
''', '''static bool ivm_jd_flushed;   /* a TB flush happened: regions hold dead code from now on */
static int  ivm_jd_on = -1;
static void ivm_jd_discard(void* start, void* end)
{
    uintptr_t ps = qemu_real_host_page_size();
    uintptr_t a = ROUND_UP((uintptr_t)start, ps), b = (uintptr_t)end & ~(ps - 1);
    if (ivm_jd_on < 0) { const char* e = getenv("IVM_JITDISCARD"); ivm_jd_on = !(e && *e == '0'); }
    if (!ivm_jd_on || !ivm_jd_flushed || tcg_splitwx_diff != 0 || b <= a) { return; }
    (void)qemu_madvise((void*)a, b - a, QEMU_MADV_DONTNEED);
}
static void tcg_region_assign(TCGContext* s, size_t curr_region)
{
    void *start, *end;

    tcg_region_bounds(curr_region, &start, &end);
    ivm_jd_discard(start, end);
''')
sub(R, '''    qemu_mutex_lock(&region.lock);
    region.current       = 0;
    region.agg_size_full = 0;
''', '''    qemu_mutex_lock(&region.lock);
    region.current       = 0;
    region.agg_size_full = 0;
    ivm_jd_flushed       = true;
''')
print("jitdiscard: ok")
