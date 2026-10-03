#!/usr/bin/env python3
"""s37: zero-fill without swap-in (apply AFTER hle-zva).
Phone evidence (4.0.32 HUD): 0.75 GB of the engine in zram, 300-800 major faults/s; the CI phone-memory model
(MEMMAX=4100M) reproduces it (0.8 GB swapped, ~900 faults/s, relaunch +31 %). DC ZVA runs ~3.3M times/s (s31
cpstats), mostly at EL1 = XNU zero-filling freshly grabbed pages. A page that iOS left on its free list goes cold, Android
swaps it out, and when XNU reuses it the very first thing it does is zero it -> a zram read (major fault, stalls the vCPU)
for data that is immediately overwritten.
 1. hle-zva generalised: the bzero loop `dc zva Xa; add Xa,Xa,#64; subs Xb,Xb,#64; b.hi .-12` with ANY Xa/Xb (the
    registers are packed into the helper's mmu argument) and at EL1 too (env IVM_ZVA1=0: EL0 only, as before).
    Unmatched EL0/EL1 DC ZVA loop heads are logged once per PC ("IVM-zva1 ...", max 16) to learn other loop shapes.
 2. Inside the helper, a whole 4 KiB host page that the loop is about to zero is checked with mincore(): if it is
    not resident (swapped out / never touched) it is discarded (ram_block_discard_range -> MADV_DONTNEED) instead of
    written, so the next access gets a fresh zero page (minor fault, no zram read). Resident pages: one 4 KiB memset.
    Same result for the guest: the page reads as zeros. TB invalidation and dirty tracking are unaffected: the fast
    path only runs when tlb_vaddr_to_host() gave a direct pointer (no TLB_NOTDIRTY, i.e. no TBs on the page and it is
    already dirty for every client).
    Active only while the engine has swap (VmSwap > 0, re-read every 2 s) -> zero cost without memory pressure.
    Env IVM_ZDISCARD=0 off, =2 always on (testing). Stats line "IVM-zd ..." on stderr every ~10 s while active.
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
def sub(rel, old, new, cnt=1):
    p = root / rel; s = p.read_text()
    if s.count(old) != cnt: sys.exit(f"zdiscard: {rel}: anchor x{s.count(old)}: {old[:70]!r}")
    p.write_text(s.replace(old, new))

T = "target/arm/tcg/translate-a64.c"
sub(T, "    if (insn != ivm_zva_w[0]) { return false; }\n",
'''    uint32_t ivm_ra = insn & 31, ivm_rb, ivm_w2;
    static int ivm_zva1 = -1, ivm_zlog = 0;
    if ((insn & ~31u) != 0xd50b7420u) { return false; }
    if (ivm_zva1 < 0) { const char* z1 = getenv("IVM_ZVA1"); ivm_zva1 = !(z1 && *z1 == '0'); }
    if (s->current_el == 1 && !ivm_zva1) { return false; }
''')
sub(T, "!ivm_zva1) { return false; }\n    if (s->base.num_insns != 1 || s->current_el != 0 || s->ss_active",
       "!ivm_zva1) { return false; }\n    if (s->base.num_insns != 1 || s->current_el > 1 || s->ss_active")
sub(T, '''    for (i = 1; i < 4; i++) {
        if (arm_ldl_code(env, &s->base, pc + 4 * i, false) != ivm_zva_w[i]) { return false; }
    }
    gen_helper_ivm_zva(tcg_env, tcg_constant_i32(s->tbid), tcg_constant_i32(get_mem_index(s)));''',
'''    (void)i;
    ivm_w2 = arm_ldl_code(env, &s->base, pc + 8, false);
    ivm_rb = ivm_w2 & 31;
    if (ivm_ra == 31 || ivm_rb == 31 || ivm_ra == ivm_rb
        || arm_ldl_code(env, &s->base, pc + 4, false) != (0x91010000u | ivm_ra << 5 | ivm_ra)
        || ivm_w2 != (0xf1010000u | ivm_rb << 5 | ivm_rb)
        || arm_ldl_code(env, &s->base, pc + 12, false) != ivm_zva_w[3]) {
        if (qatomic_read(&ivm_zlog) < 16) {
            qatomic_inc(&ivm_zlog);
            fprintf(stderr, "IVM-zva1 el%d pc %016" PRIx64 " w %08x %08x %08x %08x\\n", s->current_el, pc, insn,
                    arm_ldl_code(env, &s->base, pc + 4, false), ivm_w2, arm_ldl_code(env, &s->base, pc + 12, false));
        }
        return false;
    }
    gen_helper_ivm_zva(tcg_env, tcg_constant_i32(s->tbid),
                       tcg_constant_i32(get_mem_index(s) | ivm_ra << 8 | ivm_rb << 16));''')

H = "target/arm/tcg/helper-a64.c"
sub(H, '''static inline void ivm_zva_commit(CPUARMState* env, uint64_t x3, uint64_t x2, uint64_t old, bool done)
{
    env->xregs[3] = x3;
    env->xregs[2] = x2;''',
'''#include <sys/mman.h>
static int      ivm_zd_mode = -1;  /* 0 off, 1 while swapped, 2 always */
static int      ivm_zd_live;
static int64_t  ivm_zd_next, ivm_zd_logt;
static uint64_t ivm_zd_disc, ivm_zd_zero;
static bool ivm_zd_active(void)
{
    struct timespec ts; int64_t t;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts); t = ts.tv_sec * 1000000000LL + ts.tv_nsec;
    if (unlikely(ivm_zd_mode < 0)) { const char* e = getenv("IVM_ZDISCARD"); ivm_zd_mode = e ? atoi(e) : 1; }
    if (ivm_zd_mode != 1) { return ivm_zd_mode == 2; }
    if (unlikely(t >= qatomic_read(&ivm_zd_next))) {
        qatomic_set(&ivm_zd_next, t + 2000000000LL);
        long sw = 0; char b[4096]; int fd = open("/proc/self/status", O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, b, sizeof(b) - 1); close(fd);
            if (n > 0) { b[n] = 0; char* q = strstr(b, "VmSwap:"); if (q) { sw = atol(q + 7); } }
        }
        qatomic_set(&ivm_zd_live, sw > 0);
        if (sw > 0 && t >= ivm_zd_logt) {
            ivm_zd_logt = t + 10000000000LL;
            fprintf(stderr, "IVM-zd swap %ld kB: 4K pages discarded %" PRIu64 " zeroed %" PRIu64 "\\n", sw,
                    qatomic_read(&ivm_zd_disc), qatomic_read(&ivm_zd_zero));
        }
    }
    return qatomic_read(&ivm_zd_live);
}
/* zero one host page the guest loop fully covers: discard it if it is not resident, else memset */
static void ivm_zd_page(uint8_t* hp)
{
    unsigned char v = 1;
    if (mincore(hp, 4096, &v) == 0 && !(v & 1)) {
        ram_addr_t off;
        RAMBlock*  rb = qemu_ram_block_from_host(hp, false, &off);
        if (rb && ram_block_discard_range(rb, off, 4096) == 0) { qatomic_inc(&ivm_zd_disc); return; }
    }
    memset(hp, 0, 4096);
    qatomic_inc(&ivm_zd_zero);
}
static inline void ivm_zva_commit2(CPUARMState* env, int ra, int rb, uint64_t x3, uint64_t x2, uint64_t old, bool done)
{
    env->xregs[ra] = x3;
    env->xregs[rb] = x2;''')
# the commit helper keeps its body (flags); callers pass the registers
sub(H, "ivm_zva_commit(env, x3, x2, old, done);", "ivm_zva_commit2(env, zra, zrb, x3, x2, old, done);", 2)
sub(H, "ivm_zva_commit(env, x3, x2, old, true);", "ivm_zva_commit2(env, zra, zrb, x3, x2, old, true);")
sub(H, '''    uintptr_t ra   = GETPC();
    uint64_t  head = env->pc, x3 = env->xregs[3], x2 = env->xregs[2], old = 0, pg = -1ULL;''',
'''    uintptr_t ra   = GETPC();
    int       zra = (mmu >> 8) & 31, zrb = (mmu >> 16) & 31;
    uint64_t  head = env->pc, x3, x2, old = 0, pg = -1ULL;
    mmu &= 0xff;
    x3 = env->xregs[zra]; x2 = env->xregs[zrb];''')
sub(H, '''        if (likely(host != NULL)) {
            memset(host + (a - pg), 0, 64);''',
'''        if (likely(host != NULL)) {
            uint8_t* hz = host + (a - pg);
            if ((a & 4095) == 0 && x2 >= 4033 && n + 64 <= 1024 && TARGET_PAGE_SIZE >= 4096
                && ((uintptr_t)hz & 4095) == 0 && qemu_real_host_page_size() == 4096 && ivm_zd_active()) {
                /* the next 64 iterations zero exactly this 4 KiB page (x2 >= 4033: none of the first 63 exits) */
                ivm_zd_page(hz);
                n += 63; x3 += 63 * 64; x2 -= 63 * 64;
            } else {
                memset(hz, 0, 64);
            }''')
if "ivm_zva_commit(" in (root / H).read_text(): sys.exit("zdiscard: stale ivm_zva_commit call")
print("zdiscard: ok")
