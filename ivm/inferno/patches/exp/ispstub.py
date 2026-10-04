#!/usr/bin/env python3
"""s39 camera bring-up, step 1 (diagnostic; OFF unless env IVM_ISP=1).

Inferno drops the A13 camera block from the device tree (the `isp` node is not in KEEP_COMP and `dart-isp` is in
REM_NAMES), so AppleH10CameraInterface (AppleH10CamIn) never matches and iOS has no camera at all.
With IVM_ISP=1:
  * keep `isp` + `dart-isp` in the device tree and create the ISP DART (generic Inferno DART model)
  * map a recording stub over every ISP `reg` range: writes are stored, reads return the last written value
    (0 if never written) unless overridden by IVM_ISP_RD="off=val,off=val" (hex, region-relative, region 0..n
    encoded as (region<<28)|off); every access is logged to stderr as "[ivm-isp] ..." (first IVM_ISP_LOG, default 4000)
  * the 4 ISP interrupts are exported as AIC lines (not raised yet)
This shows what AppleH10CamIn::start / ISP_StartFirmware touch, so the fake ISP firmware (step 2) can be written
from evidence. Boot-arg camLoggingUsePrintf=1 sends the driver's own logs to the serial console.
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
def sub(rel, old, new, cnt=1):
    p = root / rel; s = p.read_text()
    if s.count(old) != cnt: sys.exit(f"ispstub: {rel}: anchor x{s.count(old)}: {old[:60]!r}")
    p.write_text(s.replace(old, new))

B = "hw/arm/boot.c"
sub(B, "        if (!found) {\n            assert_nonnull(parent);\n",
       "        if (!found && getenv(\"IVM_ISP\") && prop->len >= 9 && memcmp(prop->data, \"isp,t8030\", 9) == 0) {\n"
       "            found = true;   /* ivm ispstub: keep the camera block */\n        }\n"
       "        if (!found) {\n            assert_nonnull(parent);\n")
sub(B, "            if (memcmp(prop->data, REM_NAMES[i], size) == 0) {\n                assert_nonnull(parent);\n                DINFO(\"Removing node `%s` (blacklisted name)\"",
       "            if (memcmp(prop->data, REM_NAMES[i], size) == 0 &&\n"
       "                !(getenv(\"IVM_ISP\") && strncmp(REM_NAMES[i], \"dart-isp\", 8) == 0)) {\n"
       "                assert_nonnull(parent);\n                DINFO(\"Removing node `%s` (blacklisted name)\"")

T = "hw/arm/t8030.c"
sub(T, "static void t8030_create_sart(AppleT8030MachineState* t8030)\n", r'''/* ---- ivm ispstub (exp/ispstub.py) ---- */
typedef struct {
    MemoryRegion mr;
    int          idx;
    uint64_t     base;
} IvmIspRegion;
static GHashTable* ivm_isp_regs;   /* key (idx<<28|off) -> last written value */
static GHashTable* ivm_isp_rd;     /* key -> forced read value */
typedef struct { guint key; uint32_t wmask, rset, rclr; } IvmIspRule;
static IvmIspRule  ivm_isp_rules[64];
static int         ivm_isp_nrules;
static long        ivm_isp_nlog, ivm_isp_maxlog = 4000;

/* log with the guest LR (x30 is synced to env at slow-path memory ops); identical consecutive accesses are
 * collapsed into one "xN" line so a polling loop does not eat the log budget */
static char     ivm_isp_last_k; static int ivm_isp_last_idx; static hwaddr ivm_isp_last_off; static uint64_t ivm_isp_last_val, ivm_isp_last_lr;
static long     ivm_isp_rep;
static void ivm_isp_log(char k, IvmIspRegion* r, hwaddr off, unsigned size, uint64_t val)
{
    uint64_t lr = 0;
    if (current_cpu) { lr = ARM_CPU(current_cpu)->env.xregs[30]; }
    if (k == ivm_isp_last_k && r->idx == ivm_isp_last_idx && off == ivm_isp_last_off && val == ivm_isp_last_val && lr == ivm_isp_last_lr) {
        ivm_isp_rep++;
        if ((ivm_isp_rep & (ivm_isp_rep - 1)) == 0 && ivm_isp_rep >= 1024) { fprintf(stderr, "[ivm-isp]   ... x%ld\n", ivm_isp_rep); }
        return;
    }
    if (ivm_isp_rep) { fprintf(stderr, "[ivm-isp]   ... x%ld\n", ivm_isp_rep); ivm_isp_rep = 0; }
    ivm_isp_last_k = k; ivm_isp_last_idx = r->idx; ivm_isp_last_off = off; ivm_isp_last_val = val; ivm_isp_last_lr = lr;
    if (ivm_isp_nlog++ < ivm_isp_maxlog) {
        fprintf(stderr, "[ivm-isp] %c%d %d +0x%06" HWADDR_PRIx " %s 0x%" PRIx64 " lr=0x%" PRIx64 "\n", k, r->idx, size, off,
                k == 'R' ? "->" : "<-", val, lr);
    }
}

static uint64_t ivm_isp_read(void* opaque, hwaddr off, unsigned size)
{
    IvmIspRegion* r = opaque;
    gpointer key = GUINT_TO_POINTER(((guint)r->idx << 28) | (guint)off);
    gpointer v;
    uint64_t val = 0;
    if (ivm_isp_rd && g_hash_table_lookup_extended(ivm_isp_rd, key, NULL, &v)) { val = GPOINTER_TO_UINT(v); }
    else if (g_hash_table_lookup_extended(ivm_isp_regs, key, NULL, &v)) { val = GPOINTER_TO_UINT(v); }
    ivm_isp_log('R', r, off, size, val);
    return val;
}

static void ivm_isp_write(void* opaque, hwaddr off, uint64_t val, unsigned size)
{
    IvmIspRegion* r = opaque;
    guint key = ((guint)r->idx << 28) | (guint)off;
    int i;
    for (i = 0; i < ivm_isp_nrules; i++) {   /* write-triggered status emulation: (val & wmask) == wmask -> |rset &~rclr */
        if (ivm_isp_rules[i].key == key && (val & ivm_isp_rules[i].wmask) == ivm_isp_rules[i].wmask) {
            val = (val | ivm_isp_rules[i].rset) & ~(uint64_t)ivm_isp_rules[i].rclr;
        }
    }
    g_hash_table_insert(ivm_isp_regs, GUINT_TO_POINTER(key), GUINT_TO_POINTER((guint)val));
    ivm_isp_log('W', r, off, size, val);
}

static const MemoryRegionOps ivm_isp_ops = {
    .read = ivm_isp_read, .write = ivm_isp_write, .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 }, .impl = { .min_access_size = 4, .max_access_size = 8 },
};

static void ivm_isp_create(AppleT8030MachineState* t8030)
{
    AppleDTNode* armio = apple_dt_get_node(t8030->device_tree, "arm-io");
    AppleDTNode* isp = armio ? apple_dt_get_node(armio, "isp") : NULL;
    AppleDTProp* prop;
    uint64_t* reg;
    uint32_t i;
    const char* e;
    if (!isp || !(prop = apple_dt_get_prop(isp, "reg"))) { fprintf(stderr, "[ivm-isp] no isp node\n"); return; }
    if ((e = getenv("IVM_ISP_LOG"))) { ivm_isp_maxlog = atol(e); }
    ivm_isp_regs = g_hash_table_new(g_direct_hash, g_direct_equal);
    ivm_isp_rd = g_hash_table_new(g_direct_hash, g_direct_equal);
    g_hash_table_insert(ivm_isp_rd, GUINT_TO_POINTER(0x1800000u), GUINT_TO_POINTER(0xa0000u));   /* rISP_ISPVERSION: H10 (ver 10) */
    if ((e = getenv("IVM_ISP_RD"))) {
        gchar** kv = g_strsplit(e, ",", -1);
        for (i = 0; kv[i]; i++) {
            gchar** p2 = g_strsplit(kv[i], "=", 2);
            if (p2[0] && p2[1]) {
                g_hash_table_insert(ivm_isp_rd, GUINT_TO_POINTER((guint)g_ascii_strtoull(p2[0], NULL, 16)),
                                    GUINT_TO_POINTER((guint)g_ascii_strtoull(p2[1], NULL, 16)));
            }
            g_strfreev(p2);
        }
        g_strfreev(kv);
    }
    /* IVM_ISP_RULE="key,wmask,rset,rclr:..." (hex, key = region<<28|off); built-in defaults first */
    {
        static const IvmIspRule defaults[] = {
            { 0x1f04000, 0x2, 0x4, 0x8 },   /* ForceISPDPEIdle: force_idle req (bit1) -> ack bits[3:2] = 1 */
            { 0x1f00000, 0x2, 0x4, 0x8 },
        };
        for (i = 0; i < ARRAY_SIZE(defaults); i++) { ivm_isp_rules[ivm_isp_nrules++] = defaults[i]; }
        if ((e = getenv("IVM_ISP_RULE"))) {
            gchar** rl = g_strsplit(e, ":", -1);
            for (i = 0; rl[i] && ivm_isp_nrules < 64; i++) {
                unsigned long long a, b, c, d;
                if (sscanf(rl[i], "%llx,%llx,%llx,%llx", &a, &b, &c, &d) == 4) {
                    ivm_isp_rules[ivm_isp_nrules++] = (IvmIspRule){ (guint)a, (uint32_t)b, (uint32_t)c, (uint32_t)d };
                }
            }
            g_strfreev(rl);
        }
    }
    reg = (uint64_t*)prop->data;
    for (i = 0; i < prop->len / 16; i++) {
        IvmIspRegion* r = g_new0(IvmIspRegion, 1);
        r->idx = i; r->base = t8030->armio_base + reg[i * 2];
        memory_region_init_io(&r->mr, OBJECT(t8030), &ivm_isp_ops, r, "ivm-isp", reg[i * 2 + 1]);
        memory_region_add_subregion_overlap(get_system_memory(), r->base, &r->mr, -1);
        fprintf(stderr, "[ivm-isp] region %u at 0x%" PRIx64 " size 0x%" PRIx64 "\n", i, r->base, reg[i * 2 + 1]);
    }
}

static void t8030_create_sart(AppleT8030MachineState* t8030)
''')
sub(T, "    t8030_create_dart(t8030, \"dart-scaler\", false);\n",
       "    t8030_create_dart(t8030, \"dart-scaler\", false);\n"
       "    if (getenv(\"IVM_ISP\")) { t8030_create_dart(t8030, \"dart-isp\", false); ivm_isp_create(t8030); }\n")
print("ispstub: ok")
