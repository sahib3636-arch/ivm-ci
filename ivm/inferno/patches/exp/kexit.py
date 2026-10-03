#!/usr/bin/env python3
"""s36 kexit: cut guest-KERNEL emulation overhead (root-cause table s36: XNU = 41-47 % of all guest JIT time;
scheduler/IPC/trap paths do DAIF masking, ERET and per-thread sysreg writes constantly; cpstats: DAIF ~200k/s).

Stock QEMU ends the TB and returns to the cpu_exec main loop (exit_tb -> interrupt poll -> tb_lookup) after
  - MSR DAIFClr #imm           (+ helper with arm_rebuild_hflags)
  - MSR DAIF, Xn               (helper_lookup_cp_reg + set_cp_reg64 + rebuild_hflags + exit)
  - every other sysreg write   (rebuild_hflags + exit), e.g. TPIDR*, ELR/SPSR_EL1, SP_EL0, PAC keys, APCTL, timers
  - ERET / ERETA               (exit to the main loop "to check un-masked IRQs")
  and DAIFSet runs a full arm_rebuild_hflags.

The only reason for those exits is "an IRQ may have become takeable" or "hflags may have changed".
  * IRQ: helper ivm_irqchk sets cpu->neg.tb_exit_request when cpu->interrupt_request is non-zero. Every TB
    (except CF_NOIRQ ones) checks that flag in its prologue BEFORE executing any guest insn, so the pending IRQ is
    taken at the very next TB boundary, exactly as after exit_tb. Interrupts raised later by other threads set the
    flag themselves (tcg_handle_interrupt / qemu_cpu_kick), as before.
  * hflags: DAIF enters hflags only through single-step (MDSCR_EL1.SS); ivm_daifw rebuilds hflags + forces the
    exit in that case. The white-listed sysregs below are not inputs of arm_rebuild_hflags at all.
Effects: DAIF writes chain via goto_tb (no helper hash lookup, no hflags rebuild); white-listed sysreg writes no
longer end the TB; ERET does helper_exception_return + lookup_and_goto_ptr (flags recomputed by the helper, no
inline jc probe since EL changes). EL0 DAIF accesses, single-step and CF_NO_GOTO_PTR keep stock code.
Env IVM_KEXIT=0 restores stock behaviour (read once at first translation)."""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
def patch(rel, pairs):
    p = root / rel; s = p.read_text()
    for old, new in pairs:
        if s.count(old) != 1: sys.exit(f"kexit: {rel}: anchor x{s.count(old)}: {old[:70]!r}")
        s = s.replace(old, new)
    p.write_text(s)

patch("target/arm/tcg/helper-a64.h", [
 ("DEF_HELPER_2(exception_return, void, env, i64)\n",
  "DEF_HELPER_2(exception_return, void, env, i64)\n"
  "DEF_HELPER_FLAGS_2(ivm_daifw, TCG_CALL_NO_RWG, void, env, i64)\n"
  "DEF_HELPER_FLAGS_1(ivm_irqchk, TCG_CALL_NO_RWG, void, env)\n"),
])

patch("target/arm/tcg/helper-a64.c", [
 ("void HELPER(msr_i_daifset)(CPUARMState* env, uint32_t imm)\n",
  """/* ivm kexit: request a TB-boundary exit only when an interrupt is actually pending (see exp/kexit.py). */
void HELPER(ivm_irqchk)(CPUARMState* env)
{
    CPUState* cs = env_cpu(env);
    if (cpu_test_interrupt(cs, ~0)) { qatomic_set(&cs->neg.tb_exit_request, true); }
}

/* ivm kexit: DAIF write at EL>=1 without hflags rebuild (DAIF only matters to hflags under single-step). */
void HELPER(ivm_daifw)(CPUARMState* env, uint64_t v)
{
    CPUState* cs = env_cpu(env);
    env->daif    = v & PSTATE_DAIF;
    if (unlikely(env->cp15.mdscr_el1 & 1)) {
        arm_rebuild_hflags(env);
        qatomic_set(&cs->neg.tb_exit_request, true);
        return;
    }
    if (cpu_test_interrupt(cs, ~0)) { qatomic_set(&cs->neg.tb_exit_request, true); }
}

void HELPER(msr_i_daifset)(CPUARMState* env, uint32_t imm)
"""),
])

patch("target/arm/tcg/translate-a64.c", [
 # gate + white list (before trans_ERET, the first user)
 ("static bool trans_ERET(DisasContext* s, arg_ERET* a)\n{\n",
  """static int ivm_kexit = -1;
static bool ivm_kexit_en(void)
{
    if (unlikely(ivm_kexit < 0)) {
        const char* v = getenv("IVM_KEXIT");
        ivm_kexit     = !(v && v[0] == '0');
        fprintf(stderr, "ivm: kexit (no main-loop exit on DAIF/sysreg/ERET) %s\\n", ivm_kexit ? "on" : "off");
    }
    return ivm_kexit;
}

/* sysregs whose writes neither feed arm_rebuild_hflags nor need an immediate main-loop visit */
static bool ivm_kexit_noexit_reg(const ARMCPRegInfo* ri)
{
    static const char* const names[] = {
        "TPIDR_EL0", "TPIDRRO_EL0", "TPIDR_EL1", "ELR_EL1", "SPSR_EL1", "SP_EL0", "FAR_EL1", "ESR_EL1", "PAR_EL1",
        "CONTEXTIDR_EL1", "FPSR", "APDAKEYLO_EL1", "APDAKEYHI_EL1", "APDBKEYLO_EL1", "APDBKEYHI_EL1",
        "APGAKEYLO_EL1", "APGAKEYHI_EL1", "APIAKEYLO_EL1", "APIAKEYHI_EL1", "APIBKEYLO_EL1", "APIBKEYHI_EL1",
        "KERNELKEYLO_EL1", "KERNELKEYHI_EL1", "APCTL_EL1", "CNTV_CVAL_EL0", "CNTV_TVAL_EL0", "CNTV_CTL_EL0",
        "CNTP_CVAL_EL0", "CNTP_TVAL_EL0", "CNTP_CTL_EL0", NULL};
    if (!ri->name) { return false; }
    for (int i = 0; names[i]; i++) {
        if (!strcmp(ri->name, names[i])) { return true; }
    }
    return false;
}

static bool ivm_kexit_ok(DisasContext* s)
{
    return s->current_el >= 1 && !s->ss_active && !(tb_cflags(s->base.tb) & (CF_NO_GOTO_PTR | CF_NOIRQ)) && ivm_kexit_en();
}

static bool trans_ERET(DisasContext* s, arg_ERET* a)\n{\n"""),
 ("static bool trans_MSR_i_DAIFSET(DisasContext* s, arg_i* a)\n{\n",
  """static bool trans_MSR_i_DAIFSET(DisasContext* s, arg_i* a)
{
    if (ivm_kexit_ok(s)) {
        TCGv_i64 t = tcg_temp_new_i64();
        tcg_gen_ld_i64(t, tcg_env, offsetof(CPUARMState, daif));
        tcg_gen_ori_i64(t, t, (a->imm << 6) & PSTATE_DAIF);
        gen_helper_ivm_daifw(tcg_env, t);
        s->base.is_jmp = DISAS_TOO_MANY;
        return true;
    }
"""),
 ("static bool trans_MSR_i_DAIFCLEAR(DisasContext* s, arg_i* a)\n{\n",
  """static bool trans_MSR_i_DAIFCLEAR(DisasContext* s, arg_i* a)
{
    if (ivm_kexit_ok(s)) {
        TCGv_i64 t = tcg_temp_new_i64();
        tcg_gen_ld_i64(t, tcg_env, offsetof(CPUARMState, daif));
        tcg_gen_andi_i64(t, t, ~(uint64_t)((a->imm << 6) & PSTATE_DAIF));
        gen_helper_ivm_daifw(tcg_env, t);
        s->base.is_jmp = DISAS_TOO_MANY;
        return true;
    }
"""),
 # MSR DAIF, Xn
 ("""        else if (ri->writefn) {
            if (!tcg_ri) { tcg_ri = gen_lookup_cp_reg(key); }
            gen_helper_set_cp_reg64(tcg_env, tcg_ri, tcg_rt);
        }
        else {
            tcg_gen_st_i64(tcg_rt, tcg_env, ri->fieldoffset);
        }
    }
""",
  """        else if (ivm_daif_w) {
            gen_helper_ivm_daifw(tcg_env, tcg_rt);
        }
        else if (ri->writefn) {
            if (!tcg_ri) { tcg_ri = gen_lookup_cp_reg(key); }
            gen_helper_set_cp_reg64(tcg_env, tcg_ri, tcg_rt);
        }
        else {
            tcg_gen_st_i64(tcg_rt, tcg_env, ri->fieldoffset);
        }
    }

    if (!isread && (ivm_daif_w || (ivm_kexit_ok(s) && ivm_kexit_noexit_reg(ri)))) {
        /* ivm kexit: no hflags input. DAIF: ivm_daifw flags a pending IRQ for the next TB prologue; the other
         * white-listed regs cannot unmask an IRQ (a timer write that raises one sets tb_exit_request itself). */
        if (ivm_daif_w) { s->base.is_jmp = DISAS_TOO_MANY; }
        if (need_exit_tb) { s->base.is_jmp = DISAS_UPDATE_EXIT; }
        return;
    }
"""),
 ("    if (need_exit_tb) { s->base.is_jmp = DISAS_UPDATE_EXIT; }\n}\n\nstatic bool trans_SYS(",
  "    if (need_exit_tb) { s->base.is_jmp = DISAS_UPDATE_EXIT; }\n}\n\nstatic bool trans_SYS("),
 ("    TCGv_i64            tcg_rt;\n    uint32_t            syndrome = syn_aa64_sysregtrap(op0, op1, op2, crn, crm, rt, isread);\n",
  "    TCGv_i64            tcg_rt;\n    uint32_t            syndrome = syn_aa64_sysregtrap(op0, op1, op2, crn, crm, rt, isread);\n"
  "    bool                ivm_daif_w = false;\n"),
 # decide ivm_daif_w after the access checks (DAIF at EL1 is statically allowed via zvainline)
 ("    tcg_rt = cpu_reg(s, rt);\n\n    if (isread) {\n",
  "    tcg_rt = cpu_reg(s, rt);\n\n"
  "    ivm_daif_w = !isread && ri->name && !strcmp(ri->name, \"DAIF\") && ivm_kexit_ok(s) && !(ri->type & ARM_CP_CONST);\n\n"
  "    if (isread) {\n"),
 # ERET / ERETA
 ("""    gen_helper_exception_return(tcg_env, dst);
    /* Must exit loop to check un-masked IRQs */
    s->base.is_jmp = DISAS_EXIT;
    return true;
}

static bool trans_ERETA(""",
  """    gen_helper_exception_return(tcg_env, dst);
    if (ivm_kexit_ok(s)) {
        gen_helper_ivm_irqchk(tcg_env);
        tcg_gen_lookup_and_goto_ptr();
        s->base.is_jmp = DISAS_NORETURN;
        return true;
    }
    /* Must exit loop to check un-masked IRQs */
    s->base.is_jmp = DISAS_EXIT;
    return true;
}

static bool trans_ERETA("""),
 ("""    dst = auth_branch_target(s, dst, cpu_X[31], !a->m);

    translator_io_start(&s->base);

    gen_helper_exception_return(tcg_env, dst);
    /* Must exit loop to check un-masked IRQs */
    s->base.is_jmp = DISAS_EXIT;
""",
  """    dst = auth_branch_target(s, dst, cpu_X[31], !a->m);

    translator_io_start(&s->base);

    gen_helper_exception_return(tcg_env, dst);
    if (ivm_kexit_ok(s)) {
        gen_helper_ivm_irqchk(tcg_env);
        tcg_gen_lookup_and_goto_ptr();
        s->base.is_jmp = DISAS_NORETURN;
        return true;
    }
    /* Must exit loop to check un-masked IRQs */
    s->base.is_jmp = DISAS_EXIT;
"""),
])
print("kexit: ok")
