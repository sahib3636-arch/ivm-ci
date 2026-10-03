#!/usr/bin/env python3
"""s33 EXPERIMENT: keep the softmmu fast-TLB {mask, table} of the current mmu_idx in two reserved host registers.

Every guest load/store on an AArch64 host starts with
    sub x16, env, #ofs ; ldp x16, x17, [x16]        (CPUTLBDescFast.{mask,table} of mem_index)
    and x16, x16, addr, lsr #shift ; add x17, x17, x16 ; ldr cmp ; ldr addend ; and ; cmp ; b.ne slow
The LDP sits on the critical dependency chain of EVERY access (load-to-use ~4 cycles before the index math).
Here x27 = mask, x28 = table of the mmu_idx last loaded; the backend remembers which mmu_idx the registers hold
(ivm_tlbreg_idx) and re-emits the load only when it differs or the state is unknown. Unknown = start of a TB,
every label (control can arrive from elsewhere), after every helper call (a call can resize/flush this vCPU's TLB:
TLBI helpers, MMIO handlers flushing their own CPU). The out-of-line slow path calls the ld/st helper (which can
fill/flush the TLB) and then reloads both registers for its mmu_idx before jumping back, so the state at raddr is
exactly what the main path assumed. Asynchronous flushes from other vCPUs run as async work in cpu_exec, never
while this vCPU executes a TB. x27/x28 are callee-saved (the prologue saves x19..x28) and only used by user-mode
guest_base (not configured in system mode); they are removed from the allocator.
Env IVM_TLBREG=0 disables (code generation identical to upstream).
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
def sub(rel, old, new):
    p = root / rel; s = p.read_text()
    if s.count(old) != 1: sys.exit(f"tlbreg: {rel}: anchor x{s.count(old)}: {old[:60]!r}")
    p.write_text(s.replace(old, new))
B = "tcg/aarch64/tcg-target.c.inc"

sub(B, "static bool tcg_out_qemu_ld_slow_path(TCGContext* s, TCGLabelQemuLdst* lb)\n{",
"""/* ---- ivm exp/tlbreg ---- */
static int          ivm_tlbreg_on = -1;   /* decided once per process */
static __thread int ivm_tlbreg_idx = -1;  /* mmu_idx held in x27/x28 at the current emit point, -1 unknown */
#define IVM_TLBM TCG_REG_X27
#define IVM_TLBT TCG_REG_X28
static int tlb_mask_table_ofs(TCGContext* s, int which);
static void ivm_tlbreg_load(TCGContext* s, int mem_index)
{
    tcg_out_insn(s, 3401, SUBI, TCG_TYPE_I64, IVM_TLBM, TCG_AREG0, -tlb_mask_table_ofs(s, mem_index));
    tcg_out_insn(s, 3314, LDP, IVM_TLBM, IVM_TLBT, IVM_TLBM, 0, 1, 0);
}

static bool tcg_out_qemu_ld_slow_path(TCGContext* s, TCGLabelQemuLdst* lb)
{""")
sub(B, """    tcg_out_ld_helper_ret(s, lb, false, &ldst_helper_param);
    tcg_out_goto(s, lb->raddr);""", """    tcg_out_ld_helper_ret(s, lb, false, &ldst_helper_param);
    if (ivm_tlbreg_on) { ivm_tlbreg_load(s, get_mmuidx(lb->oi)); } /* ivm tlbreg: state at raddr */
    tcg_out_goto(s, lb->raddr);""")
sub(B, """    tcg_out_call_int(s, qemu_st_helpers[opc & MO_SIZE]);
    tcg_out_goto(s, lb->raddr);""", """    tcg_out_call_int(s, qemu_st_helpers[opc & MO_SIZE]);
    if (ivm_tlbreg_on) { ivm_tlbreg_load(s, get_mmuidx(lb->oi)); } /* ivm tlbreg: state at raddr */
    tcg_out_goto(s, lb->raddr);""")
sub(B, """    tcg_out_insn(s, 3401, SUBI, addr_type, TCG_REG_TMP0, TCG_AREG0, -tlb_mask_table_ofs(s, mem_index));
    tcg_out_insn(s, 3314, LDP, TCG_REG_TMP0, TCG_REG_TMP1, TCG_REG_TMP0, 0, 1, 0);

    /* Extract the TLB index from the address into X0.  */
    tcg_out_insn(s, 3502S, AND_LSR, TCG_TYPE_I64, TCG_REG_TMP0, TCG_REG_TMP0, addr_reg,
                 TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS);

    /* Add the tlb_table pointer, forming the CPUTLBEntry address. */
    tcg_out_insn(s, 3502, ADD, 1, TCG_REG_TMP1, TCG_REG_TMP1, TCG_REG_TMP0);
""", """    if (ivm_tlbreg_on) {
        /* ivm tlbreg: {mask, table} live in x27/x28 */
        if (ivm_tlbreg_idx != (int)mem_index) {
            ivm_tlbreg_load(s, mem_index);
            ivm_tlbreg_idx = mem_index;
        }
        tcg_out_insn(s, 3502S, AND_LSR, TCG_TYPE_I64, TCG_REG_TMP0, IVM_TLBM, addr_reg,
                     TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS);
        tcg_out_insn(s, 3502, ADD, 1, TCG_REG_TMP1, IVM_TLBT, TCG_REG_TMP0);
    }
    else {
    tcg_out_insn(s, 3401, SUBI, addr_type, TCG_REG_TMP0, TCG_AREG0, -tlb_mask_table_ofs(s, mem_index));
    tcg_out_insn(s, 3314, LDP, TCG_REG_TMP0, TCG_REG_TMP1, TCG_REG_TMP0, 0, 1, 0);

    /* Extract the TLB index from the address into X0.  */
    tcg_out_insn(s, 3502S, AND_LSR, TCG_TYPE_I64, TCG_REG_TMP0, TCG_REG_TMP0, addr_reg,
                 TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS);

    /* Add the tlb_table pointer, forming the CPUTLBEntry address. */
    tcg_out_insn(s, 3502, ADD, 1, TCG_REG_TMP1, TCG_REG_TMP1, TCG_REG_TMP0);
    }
""")
sub(B, "    tcg_regset_set_reg(s->reserved_regs, TCG_REG_TMP2);\n",
"""    tcg_regset_set_reg(s->reserved_regs, TCG_REG_TMP2);
    if (ivm_tlbreg_on < 0) {
        const char* e = getenv("IVM_TLBREG");
        ivm_tlbreg_on = !(e && e[0] == '0');
        fprintf(stderr, "ivm: tlbreg %s\\n", ivm_tlbreg_on ? "on" : "off");
    }
    if (ivm_tlbreg_on) {
        tcg_regset_set_reg(s->reserved_regs, IVM_TLBM);
        tcg_regset_set_reg(s->reserved_regs, IVM_TLBT);
    }
""")

T = "tcg/tcg.c"
sub(T, """int tcg_gen_code(TCGContext* s, TranslationBlock* tb, uint64_t pc_start)
{
    int    i, num_insns;
    TCGOp* op;
""", """int tcg_gen_code(TCGContext* s, TranslationBlock* tb, uint64_t pc_start)
{
    int    i, num_insns;
    TCGOp* op;

    ivm_tlbreg_idx = -1; /* ivm tlbreg: unknown at TB start */
""")
sub(T, """            case INDEX_op_set_label:
                tcg_reg_alloc_bb_end(s, s->reserved_regs);
                tcg_out_label(s, arg_label(op->args[0]));
                break;
            case INDEX_op_call:
                assert_carry_dead(s);
                tcg_reg_alloc_call(s, op);
                break;""", """            case INDEX_op_set_label:
                tcg_reg_alloc_bb_end(s, s->reserved_regs);
                tcg_out_label(s, arg_label(op->args[0]));
                ivm_tlbreg_idx = -1; /* ivm tlbreg: control may arrive from elsewhere */
                break;
            case INDEX_op_call:
                assert_carry_dead(s);
                tcg_reg_alloc_call(s, op);
                ivm_tlbreg_idx = -1; /* ivm tlbreg: the helper may have resized/flushed the TLB */
                break;""")
print("tlbreg: applied")
