#!/usr/bin/env python3
"""s36 cntfast: generic-timer counter reads (MRS CNTVCT/CNTPCT[SS]_EL0) in one helper call.
cpstats: ~280k/s CNTVCT reads (XNU spin-lock timeouts, mach_absolute_time in user space via the commpage, scheduler
timestamps). Stock code per read: EL1 = helper_lookup_cp_reg (hash lookup) + helper_get_cp_reg64 -> readfn;
EL0 = helper_access_check_cp_reg (hash lookup + accessfn) + lookup + get. Here: ri is matched at translate time
(readfn/accessfn pointer identity) and the read becomes helper_ivm_cnt (EL1) or helper_ivm_cnt_el0 (inline
gt_counter_access check; on a denied access it calls the stock access_check helper, which raises the exact same
exception). Only on CPUs without EL2 and without FGT/NV (the A13 machine). Env IVM_CNTFAST=0 = stock."""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
def patch(rel, pairs):
    p = root / rel; s = p.read_text()
    for old, new in pairs:
        if s.count(old) != 1: sys.exit(f"cntfast: {rel}: anchor x{s.count(old)}: {old[:70]!r}")
        s = s.replace(old, new)
    p.write_text(s)

h = (root / "target/arm/helper.c").read_text()
h += '''
/* ivm cntfast (exp/cntfast.py): counter reads without the cpreg hash lookups */
int ivm_cnt_kind(const ARMCPRegInfo* ri)
{
    static int en = -1;
    if (en < 0) {
        const char* e = getenv("IVM_CNTFAST");
        en            = !(e && e[0] == '0');
        fprintf(stderr, "ivm: cntfast %s\\n", en ? "on" : "off");
    }
    if (!en) { return 0; }
    if (ri->readfn == gt_virt_cnt_read && ri->accessfn == gt_vct_access) { return 1; }
    if (ri->readfn == gt_cnt_read && ri->accessfn == gt_pct_access) { return 2; }
    return 0;
}

uint64_t ivm_cnt_value(CPUARMState* env, int kind) { return kind == 1 ? gt_virt_cnt_read(env, NULL) : gt_cnt_read(env, NULL); }

bool ivm_cnt_access_ok(CPUARMState* env, int kind)
{ return gt_counter_access(env, kind == 1 ? GTIMER_VIRT : GTIMER_PHYS, true) == CP_ACCESS_OK; }
'''
(root / "target/arm/helper.c").write_text(h)

patch("target/arm/tcg/helper-a64.h", [
 ("DEF_HELPER_2(exception_return, void, env, i64)\n",
  "DEF_HELPER_2(exception_return, void, env, i64)\n"
  "DEF_HELPER_FLAGS_2(ivm_cnt, TCG_CALL_NO_RWG, i64, env, i32)\n"
  "DEF_HELPER_4(ivm_cnt_el0, i64, env, i32, i32, i32)\n"),
])

patch("target/arm/tcg/helper-a64.c", [
 ("void HELPER(msr_i_daifset)(CPUARMState* env, uint32_t imm)\n",
  """uint64_t ivm_cnt_value(CPUARMState* env, int kind);
bool     ivm_cnt_access_ok(CPUARMState* env, int kind);

uint64_t HELPER(ivm_cnt)(CPUARMState* env, uint32_t kind) { return ivm_cnt_value(env, kind); }

uint64_t HELPER(ivm_cnt_el0)(CPUARMState* env, uint32_t kind, uint32_t key, uint32_t syndrome)
{
    if (unlikely(!ivm_cnt_access_ok(env, kind))) {
        HELPER(access_check_cp_reg)(env, key, syndrome, 1, 0); /* raises (pc already synced) */
    }
    return ivm_cnt_value(env, kind);
}

void HELPER(msr_i_daifset)(CPUARMState* env, uint32_t imm)
"""),
])

patch("target/arm/tcg/translate-a64.c", [
 ("static void handle_sys(DisasContext* s, bool isread, unsigned int op0, unsigned int op1, unsigned int op2,\n",
  "int ivm_cnt_kind(const ARMCPRegInfo* ri);\n\n"
  "static void handle_sys(DisasContext* s, bool isread, unsigned int op0, unsigned int op1, unsigned int op2,\n"),
 ("""        gen_sysreg_undef(s, isread, op0, op1, op2, crn, crm, rt);
        return;
    }

    if (s->nv2 && ri->nv2_redirect_offset) {""",
  """        gen_sysreg_undef(s, isread, op0, op1, op2, crn, crm, rt);
        return;
    }

    if (isread && crn == 14 && !s->fgt_active && !s->nv && !arm_dc_feature(s, ARM_FEATURE_EL2)) {
        int ivm_k = ivm_cnt_kind(ri);
        if (ivm_k) {
            TCGv_i64 d = cpu_reg(s, rt);
            if (s->current_el == 0) {
                gen_a64_update_pc(s, 0);
                gen_helper_ivm_cnt_el0(d, tcg_env, tcg_constant_i32(ivm_k), tcg_constant_i32(key),
                                       tcg_constant_i32(syndrome));
            }
            else {
                gen_helper_ivm_cnt(d, tcg_env, tcg_constant_i32(ivm_k));
            }
            return;
        }
    }

    if (s->nv2 && ri->nv2_redirect_offset) {"""),
])
print("cntfast: ok")
