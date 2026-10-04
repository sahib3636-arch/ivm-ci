#!/usr/bin/env python3
"""s39 diagnostic: guest PC trace points (OFF unless env IVM_KTRACE is set).

IVM_KTRACE="0xffff...,0xffff..." (hex guest VAs, max 32). When the translator emits an instruction at one of those
PCs it first emits a helper call that prints "[ktrace] pc x0..x7 lr" to stderr every time the instruction runs
(first IVM_KTRACE_N hits, default 4000). Zero cost when unset (one getenv at first translation).
Used to see IOKit user-client selectors / driver entry points of AppleH10CamIn without symbols at runtime.
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
def sub(rel, old, new):
    p = root / rel; s = p.read_text()
    if s.count(old) != 1: sys.exit(f"ktrace: {rel}: anchor x{s.count(old)}: {old[:60]!r}")
    p.write_text(s.replace(old, new))

sub("target/arm/tcg/helper-a64.h", "DEF_HELPER_FLAGS_2(udiv64, TCG_CALL_NO_RWG_SE, i64, i64, i64)\n",
    "DEF_HELPER_FLAGS_2(udiv64, TCG_CALL_NO_RWG_SE, i64, i64, i64)\nDEF_HELPER_2(ivm_ktrace, void, env, i64)\n"
    "DEF_HELPER_2(ivm_slide, void, env, i64)\nDEF_HELPER_2(ivm_utrace, void, env, i64)\nDEF_HELPER_2(ivm_oslog, void, env, i64)\nDEF_HELPER_2(ivm_figlog, void, env, i64)\nDEF_HELPER_2(ivm_koslog, void, env, i64)\nDEF_HELPER_2(ivm_lockfix, void, env, i64)\n")
p = root / "target/arm/tcg/helper-a64.c"
p.write_text(p.read_text() + r'''
/* ---- iVM ktrace (exp/ktrace.py) ---- */
static long ivm_ktrace_hits, ivm_ktrace_max = -1;
void HELPER(ivm_ktrace)(CPUARMState* env, uint64_t pc)
{
    if (ivm_ktrace_max < 0) {
        const char* e = getenv("IVM_KTRACE_N");
        ivm_ktrace_max = e ? atol(e) : 4000;
    }
    if (ivm_ktrace_hits++ >= ivm_ktrace_max) { return; }
    fprintf(stderr, "[ktrace] %" PRIx64 " x0=%" PRIx64 " x1=%" PRIx64 " x2=%" PRIx64 " x3=%" PRIx64 " x4=%" PRIx64
            " x5=%" PRIx64 " x6=%" PRIx64 " x7=%" PRIx64 " lr=%" PRIx64 "\n", pc, env->xregs[0], env->xregs[1],
            env->xregs[2], env->xregs[3], env->xregs[4], env->xregs[5], env->xregs[6], env->xregs[7], env->xregs[30]);
    if (getenv("IVM_KTRACE_SS")) {   /* x0 = arm_saved_state*: print saved user lr/sp/pc (+0xf8/+0x100/+0x108) */
        uint64_t ss[3] = { 0, 0, 0 };
        cpu_memory_rw_debug(env_cpu(env), env->xregs[0] + 0xf8, ss, sizeof(ss), false);
        fprintf(stderr, "[ktrace]   ss lr=%" PRIx64 " sp=%" PRIx64 " pc=%" PRIx64 "\n", ss[0], ss[1], ss[2]);
        {   /* walk the saved user frame-pointer chain */
            uint64_t fp = 0, fr[2];
            int      d;
            cpu_memory_rw_debug(env_cpu(env), env->xregs[0] + 0xf0, &fp, 8, false);
            for (d = 0; d < 24 && fp && !(fp & 7); d++) {
                if (cpu_memory_rw_debug(env_cpu(env), fp, fr, sizeof(fr), false)) { break; }
                fprintf(stderr, "[ktrace]   bt#%d %" PRIx64 "\n", d, fr[1] & 0xfffffffffULL);
                fp = fr[0];
            }
        }
    }
}
''' + (pathlib.Path(__file__).parent / 'ktrace_u.c').read_text())
sub("target/arm/tcg/translate-a64.c", "    s->pc_curr      = pc;\n    insn            = arm_ldl_code(env, &s->base, pc, s->sctlr_b);\n",
    r'''    {   /* ivm ktrace (exp/ktrace.py) */
        static int      ivm_kt_n = -1;
        static uint64_t ivm_kt_pc[32];
        int             k;
        if (ivm_kt_n < 0) {
            const char* e = getenv("IVM_KTRACE");
            ivm_kt_n = 0;
            while (e && *e && ivm_kt_n < 32) {
                char* end;
                ivm_kt_pc[ivm_kt_n++] = strtoull(e, &end, 16);
                e = (*end == ',') ? end + 1 : NULL;
            }
        }
        for (k = 0; k < ivm_kt_n; k++) {
            if (ivm_kt_pc[k] == pc) { gen_helper_ivm_ktrace(tcg_env, tcg_constant_i64(pc)); break; }
        }
        static int      ivm_ut_n = -1;
        static uint64_t ivm_ut_pc[32], ivm_slide_pc, ivm_oslog_pc, ivm_figlog_pc, ivm_koslog_pc;
        extern uint64_t ivm_dsc_slide;
        if (ivm_ut_n < 0) {
            const char* e = getenv("IVM_UTRACE");
            ivm_ut_n = 0;
            while (e && *e && ivm_ut_n < 32) {
                char* end;
                ivm_ut_pc[ivm_ut_n++] = strtoull(e, &end, 16);
                e = (*end == ',') ? end + 1 : NULL;
            }
            e = getenv("IVM_SLIDEPC");
            ivm_slide_pc = e ? strtoull(e, NULL, 16) : 0;
            e = getenv("IVM_OSLOG");
            ivm_oslog_pc = e ? strtoull(e, NULL, 16) : 0;
            e = getenv("IVM_KOSLOG");
            ivm_koslog_pc = e ? strtoull(e, NULL, 16) : 0;
            e = getenv("IVM_FIGLOG");
            ivm_figlog_pc = e ? strtoull(e, NULL, 16) : 0;
            e = getenv("IVM_DSC_SLIDE");
            if (e) {
                ivm_dsc_slide = strtoull(e, NULL, 16);
            }
        }
        if (ivm_koslog_pc && pc == ivm_koslog_pc) {
            gen_helper_ivm_koslog(tcg_env, tcg_constant_i64(pc));
        }
        if (ivm_slide_pc && pc == ivm_slide_pc) {
            gen_helper_ivm_slide(tcg_env, tcg_constant_i64(pc));
        }
        if (ivm_dsc_slide && s->current_el == 0) {
            uint64_t upc = pc - ivm_dsc_slide;
            extern uint64_t ivm_lockfix_pc;
            if (ivm_lockfix_pc && upc == ivm_lockfix_pc) {
                gen_helper_ivm_lockfix(tcg_env, tcg_constant_i64(pc));
            }
            if (ivm_oslog_pc && upc == ivm_oslog_pc) {
                gen_helper_ivm_oslog(tcg_env, tcg_constant_i64(pc));
            }
            if (ivm_figlog_pc && upc == ivm_figlog_pc) {
                gen_helper_ivm_figlog(tcg_env, tcg_constant_i64(pc));
            }
            for (k = 0; k < ivm_ut_n; k++) {
                if (ivm_ut_pc[k] == upc) { gen_helper_ivm_utrace(tcg_env, tcg_constant_i64(pc)); break; }
            }
        }
    }
    s->pc_curr      = pc;
    insn            = arm_ldl_code(env, &s->base, pc, s->sctlr_b);
''')
print("ktrace: ok")
