#!/usr/bin/env python3
"""s37: drop stale JIT code pages before reusing a code-cache region (swap-in avoidance).
After a TB flush the code buffer (tb-size 1024 MB) is refilled from the start. The region about to be written was last
written minutes ago, so under memory pressure Android has already swapped it to zram -> every first store of new code
into it is a major fault (zram read of dead code). Now, when a region is (re)assigned to a TCG context after a flush,
its pages are discarded first and RSS can drop by the stale part of the cache (less pressure on the guest RAM).
v1 (MADV_DONTNEED) under the CI memory cap: major faults -21 %, relaunch -6.6 %, first launch -4.5 %, but swipe
commit fps -3 % (every recycled page refaulted, THP backing of the buffer split). v2 uses MADV_FREE (see below).
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
#ifdef MADV_FREE
    /* v2: MADV_FREE, not DONTNEED: without pressure the pages stay mapped (the next code write costs nothing and the
     * THP backing survives); under pressure the kernel drops them instead of writing them to zram, and pages that
     * are already in zram lose their swap slot -> the next write is a zero-fill minor fault, never a zram read */
    if (madvise((void*)a, b - a, MADV_FREE) == 0) { return; }
#endif
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
p = root / R; t = p.read_text()
t = t.replace('#include "qemu/osdep.h"\n', '#include "qemu/osdep.h"\n#include <sys/mman.h>\n', 1); p.write_text(t)
print("jitdiscard: ok")
