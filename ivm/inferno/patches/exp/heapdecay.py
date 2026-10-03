#!/usr/bin/env python3
"""s37: let Scudo hand free heap pages back to the kernel (swap-in avoidance).
FAULTREC on the CI phone-memory model (frS, MEMMAX=4100M, 120 s of app launches): 29 % of the engine's major faults hit
the Scudo heap ([anon:scudo:primary] 108 MB, 92 MB of it in swap), 86 % of those taken inside libc (malloc/free and
mem* on cold chunks). Bionic only releases freed Scudo pages when M_DECAY_TIME is set (apps get it from the zygote;
our engine is a plain exec'd process, so it never did) -> free chunks go cold, get swapped, and are read back from
zram when reused. Now: mallopt(M_DECAY_TIME, 1) at start-up (periodic release of free pages -> reuse = cheap
zero-fill) and mallopt(M_PURGE) after every TB flush (the flush frees a lot of TB bookkeeping at once).
Bionic only (no-op elsewhere). Env IVM_HEAPDECAY=0 disables.
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
def sub(rel, old, new):
    p = root / rel; s = p.read_text()
    if s.count(old) != 1: sys.exit(f"heapdecay: {rel}: anchor x{s.count(old)}: {old[:70]!r}")
    p.write_text(s.replace(old, new))
sub("system/main.c", '''int main(int argc, char** argv)
{
    qemu_init(argc, argv);
''', '''#ifdef __BIONIC__
#include <malloc.h>
#endif
int main(int argc, char** argv)
{
#ifdef __BIONIC__
    {
        const char* e = getenv("IVM_HEAPDECAY");
        if (!(e && *e == '0')) { fprintf(stderr, "IVM-heapdecay M_DECAY_TIME rc %d\\n", mallopt(M_DECAY_TIME, 1)); }
    }
#endif
    qemu_init(argc, argv);
''')
sub("tcg/region.c", '''    qemu_mutex_unlock(&region.lock);

    tcg_region_tree_reset_all();
}''', '''    qemu_mutex_unlock(&region.lock);

    tcg_region_tree_reset_all();
#if defined(__BIONIC__) && defined(M_PURGE)
    {
        const char* e = getenv("IVM_HEAPDECAY");
        if (!(e && *e == '0')) { mallopt(M_PURGE, 0); }
    }
#endif
}''')
p = root / "tcg/region.c"; s = p.read_text()
s = s.replace('#include "qemu/osdep.h"\n', '#include "qemu/osdep.h"\n#ifdef __BIONIC__\n#include <malloc.h>\n#endif\n', 1)
p.write_text(s)
print("heapdecay: ok")
