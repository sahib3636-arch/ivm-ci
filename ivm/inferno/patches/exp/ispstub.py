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
sub(T, "static void t8030_rtkit_seg_prop_setup(AppleDTNode* iop_nub, hwaddr base, uint32_t size)\n",
       "static hwaddr ivm_isp_fw_phys;   /* ivm ispstub: fake preloaded fw carve-out */\n"
       "static void t8030_rtkit_seg_prop_setup(AppleDTNode* iop_nub, hwaddr base, uint32_t size)\n")
_FW = (pathlib.Path(__file__).resolve().parent / "ispstub_fw.c").read_text()
_FW = _FW.replace("@@IVM_FRAMES@@", (pathlib.Path(__file__).resolve().parent / "ispstub_frames.c").read_text())
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
    if (!ivm_isp_maxlog) { return; }   /* IVM_ISP_LOG=0 (shipped app): no MMIO trace at all */
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

@@IVM_FW@@static uint64_t ivm_isp_read(void* opaque, hwaddr off, unsigned size)
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
    if (r->idx == 0) { ivm_isp_fw_write(off, val); }
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
    {   /* AppleH10CamIn::start maps a hard-coded per-version register page (v10: 0x23b110000, ISP_Suspend clears
         * bit 0x20 there); unbacked in the machine model -> data abort.  Back it with an extra recording region. */
        IvmIspRegion* r = g_new0(IvmIspRegion, 1);
        r->idx = 4; r->base = 0x23b110000ULL;
        memory_region_init_io(&r->mr, OBJECT(t8030), &ivm_isp_ops, r, "ivm-isp-x", 0x4000);
        memory_region_add_subregion_overlap(get_system_memory(), r->base, &r->mr, -1);
    }
    {   /* ISP DMA view for decoding command packets */
        Object* d = object_property_get_link(OBJECT(t8030), "dart-isp", NULL);
        AppleDTNode* m = apple_dt_get_node(t8030->device_tree, "arm-io/dart-isp/mapper-isp");
        AppleDTProp* mp = m ? apple_dt_get_prop(m, "reg") : NULL;
        if (d && mp) {
            address_space_init(&ivm_isp_dma_as, MEMORY_REGION(apple_dart_iommu_mr(APPLE_DART(d), ldl_le_p(mp->data))), "ivm-isp.dma");
            ivm_isp_dma_ok = true;
        }
    }
    if ((prop = apple_dt_get_prop(isp, "interrupts")) && prop->len >= 4) {
        ivm_isp_irq = qdev_get_gpio_in(DEVICE(t8030->aic), ldl_le_p(prop->data));
        fprintf(stderr, "[ivm-isp] irq %u\n", ldl_le_p(prop->data));
    }
}

static void t8030_create_sart(AppleT8030MachineState* t8030)
''')
sub(T, "    t8030_create_dart(t8030, \"dart-scaler\", false);\n",
       "    t8030_create_dart(t8030, \"dart-scaler\", false);\n"
       "    if (getenv(\"IVM_ISP\")) { t8030_create_dart(t8030, \"dart-isp\", false); ivm_isp_create(t8030); }\n")

# fake "iBoot-preloaded" ISP firmware: AppleH10CamIn then skips the userland ISP_LoadFirmware path (applecamerad passes
# len 0, which on real hardware is fine because iBoot preloaded the firmware) and maps __TEXT/__DATA from
# `segment-ranges` (2 x {u64 phys, u64 iova, u64 remap, u32 size, u32 pad}) into the ISP DART.
sub(T, '    t8030_rtkit_mem_setup(t8030, ca, "ans", "iop-ans-nub", ANS_SIZE);\n',
       '    t8030_rtkit_mem_setup(t8030, ca, "ans", "iop-ans-nub", ANS_SIZE);\n'
       '    if (getenv("IVM_ISP")) {   /* ivm ispstub: carve out a fake preloaded ISP firmware (TEXT 1M + DATA 1M) */\n'
       '        AppleDTNode* ivm_aio = apple_dt_get_node(t8030->device_tree, "arm-io");\n'
       '        AppleDTNode* ivm_isp = ivm_aio ? apple_dt_get_node(ivm_aio, "isp") : NULL;\n'
       '        if (ivm_isp) {\n'
       '            uint64_t ivm_seg[8];\n'
       '            hwaddr   ivm_fw = carveout_alloc_mem(ca, 2 * MiB);\n'
       '            ivm_seg[0] = ivm_fw;           ivm_seg[1] = 0x10000;  ivm_seg[2] = 0x10000;  ivm_seg[3] = 1 * MiB;\n'
       '            ivm_seg[4] = ivm_fw + 1 * MiB; ivm_seg[5] = 0x110000; ivm_seg[6] = 0x110000; ivm_seg[7] = 1 * MiB;\n'
       '            apple_dt_set_prop(ivm_isp, "segment-ranges", sizeof(ivm_seg), ivm_seg);\n'
       '            apple_dt_set_prop_u32(ivm_isp, "pre-loaded", 1);\n'
       '            ivm_isp_fw_phys = ivm_fw;\n'
       '            fprintf(stderr, "[ivm-isp] fake preloaded fw at 0x%" PRIx64 "\\n", (uint64_t)ivm_fw);\n'
       '        }\n'
       '    }\n')
# the kext maps the preloaded fw at DVA 0 (mapFwCTRRRegion: iovmInsert at 0); keep dart-isp vm-base 0
sub(T, "    if (prop != NULL && ldl_le_p(prop->data) == 0) { stl_le_p(prop->data, 0x4000); }\n",
       "    if (prop != NULL && ldl_le_p(prop->data) == 0 && !(getenv(\"IVM_ISP\") && strcmp(name, \"dart-isp\") == 0)) { stl_le_p(prop->data, 0x4000); }\n")
p_ = root / T; s_ = p_.read_text(); assert s_.count("@@IVM_FW@@") == 1; p_.write_text(s_.replace("@@IVM_FW@@", _FW))
print("ispstub: ok")

# s39 isp43: env-gated M2 scaler trace (IVM_SCALER_LOG=N -> first N jobs to stderr as "[ivm-msr]")
S = "hw/display/apple_scaler.c"
sub(S, "    if (src_ok && dst_ok) { apple_scaler_process(scaler, &src, &dst); }\n",
       "    {\n        static int ivm_msr_n = -1;\n"
       "        if (ivm_msr_n < 0) { const char* e = getenv(\"IVM_SCALER_LOG\"); ivm_msr_n = e ? atoi(e) : 0; }\n"
       "        if (ivm_msr_n > 0) {\n            ivm_msr_n--;\n"
       "            uint8_t sb[4] = {0}, sc[4] = {0};\n"
       "            if (src_ok) { dma_memory_read(&scaler->dma_as, src.base[LUMA] + src.stride[LUMA] * (src.height / 2) + src.width / 2, sb, 4, MEMTXATTRS_UNSPECIFIED);\n"
       "                          if (apple_scaler_layout_is_biplanar(src.layout)) dma_memory_read(&scaler->dma_as, src.base[CHROMA] + src.stride[CHROMA] * (src.height / 4) + src.width / 2, sc, 4, MEMTXATTRS_UNSPECIFIED); }\n"
       "            fprintf(stderr, \"[ivm-msr] fc=%u src fmt=0x%x sw=0x%x %s %ux%u st %u/%u base 0x%llx/0x%llx ok=%d Y=%02x%02x%02x%02x C=%02x%02x%02x%02x | \"\n"
       "                    \"dst fmt=0x%x sw=0x%x %s %ux%u st %u/%u base 0x%llx/0x%llx ok=%d rot=0x%x\\n\",\n"
       "                    qatomic_read(&scaler->frame_count), scaler->srcdst[SOURCE].format, scaler->srcdst[SOURCE].swizzle, apple_scaler_stringify_format(src.format), src.width, src.height, src.stride[LUMA], src.stride[CHROMA],\n"
       "                    (unsigned long long)src.base[LUMA], (unsigned long long)src.base[CHROMA], src_ok, sb[0], sb[1], sb[2], sb[3], sc[0], sc[1], sc[2], sc[3],\n"
       "                    scaler->srcdst[DEST].format, scaler->srcdst[DEST].swizzle, apple_scaler_stringify_format(dst.format), dst.width, dst.height, dst.stride[LUMA], dst.stride[CHROMA],\n"
       "                    (unsigned long long)dst.base[LUMA], (unsigned long long)dst.base[CHROMA], dst_ok, scaler->flip_rotate_cfg);\n"
       "        }\n    }\n"
       "    if (src_ok && dst_ok) { apple_scaler_process(scaler, &src, &dst); }\n")

# s39 isp44: shadow every scaler register write; dump the source register block for unsupported (compressed) jobs
sub(S, "    // SCALER_INFO(\"0x\" HWADDR_FMT_plx \" <- 0x\" HWADDR_FMT_plx, addr, data);\n\n    addr >>= 2;\n",
       "    // SCALER_INFO(\"0x\" HWADDR_FMT_plx \" <- 0x\" HWADDR_FMT_plx, addr, data);\n\n    addr >>= 2;\n"
       "    if (addr < 0x200) { ivm_msr_shadow[addr] = (uint32_t)data; }\n")
sub(S, "static bool apple_scaler_surface_init(AppleScalerSurface* surface, AppleScalerState* scaler, SourceDest srcdst)\n",
       "static uint32_t ivm_msr_shadow[0x200];   /* ivm: last value written to each scaler register */\n"
       "static bool apple_scaler_surface_init(AppleScalerSurface* surface, AppleScalerState* scaler, SourceDest srcdst)\n")
sub(S, "                    (unsigned long long)dst.base[LUMA], (unsigned long long)dst.base[CHROMA], dst_ok, scaler->flip_rotate_cfg);\n",
       "                    (unsigned long long)dst.base[LUMA], (unsigned long long)dst.base[CHROMA], dst_ok, scaler->flip_rotate_cfg);\n"
       "            if (!src_ok) {\n                fprintf(stderr, \"[ivm-msr] regs\");\n"
       "                for (int i = 0x100 / 4; i < 0x200 / 4; i++) { if (ivm_msr_shadow[i]) fprintf(stderr, \" %03x=%x\", i * 4, ivm_msr_shadow[i]); }\n"
       "                fprintf(stderr, \"\\n\");\n            }\n")

# s39 isp45: "linear-compressed" convention. The only producer of compressed camera surfaces in the VM is our fake ISP
# and the only consumer/producer on the other side is this scaler (no GPU), so a compressed/indirect surface is
# treated as plain linear data at the plane base (COMP_HEADER_BASE regs 0x1a4/0x1a8 (+0x100 for dst); the fake ISP
# writes linear NV12 at h2t addr0/addr1 = the same IOSurface plane bases) with stride = align64(row bytes).
# IVM_MSR_NOLIN disables.
sub(S, "    if (surface->layout == SCALER_LAYOUT_NONE || surface->width == 0 || surface->height == 0) { return false; }\n",
       "    if (surface->format == APPLE_SCALER_FORMAT_UNKNOWN && !getenv(\"IVM_MSR_NOLIN\")) {\n"
       "        uint32_t f2 = cfg->format & ~((1u << 14) | (0xfu << 16) | (1u << 26) | (0xfu << 28));\n"
       "        AppleScalerFormat fm = apple_scaler_convert_hw_format(f2, cfg->swizzle);\n"
       "        if (f2 != cfg->format && fm != APPLE_SCALER_FORMAT_UNKNOWN && surface->width && surface->height) {\n"
       "            AppleScalerLayout ly = apple_scaler_format_layout(fm);\n"
       "            uint32_t dp = apple_scaler_format_depth(fm);\n"
       "            uint32_t hb = (0x1a4 + (srcdst == SOURCE ? 0 : 0x100)) / 4;\n"
       "            if (ly != SCALER_LAYOUT_NONE && ivm_msr_shadow[hb]) {\n"
       "                uint32_t rb = surface->width * apple_scaler_luma_bpp(ly, dp);\n"
       "                surface->format = fm; surface->layout = ly; surface->depth = dp;\n"
       "                surface->stride[LUMA] = surface->stride[CHROMA] = (rb + 63) & ~63u;\n"
       "                surface->base[LUMA] = ivm_msr_shadow[hb];\n"
       "                surface->base[CHROMA] = ivm_msr_shadow[hb + 1];\n"
       "                return true;\n"
       "            }\n"
       "        }\n"
       "    }\n"
       "    if (surface->layout == SCALER_LAYOUT_NONE || surface->width == 0 || surface->height == 0) { return false; }\n")

# s39 isp47: display pipe layer blending. With the camera viewfinder, IOMFB uses two generic pipes (video BGRA from the
# M2 scaler + UI layer with a transparent hole). Inferno drew every enabled pipe with PIXMAN_OP_SRC, so the later
# layer's transparent pixels wiped the earlier one (black viewfinder). Draw the first enabled pipe with SRC and the
# rest with OVER (CA surfaces are premultiplied). IVM_ADP_REV reverses pipe order, IVM_ADP_SRC restores old behaviour,
# IVM_ADP_LOG=N logs N two-layer frames.
A = "hw/display/apple_displaypipe_v4.c"
sub(A, "static void adp_v4_gp_draw(ADPV4GenPipe* genpipe, AddressSpace* dma_as, pixman_image_t* disp_image,\n                           QemuConsole* console)\n{\n",
       "static int ivm_adp_drawn;   /* ivm: pipes already composited in the current frame */\n"
       "static void adp_v4_gp_draw(ADPV4GenPipe* genpipe, AddressSpace* dma_as, pixman_image_t* disp_image,\n                           QemuConsole* console)\n{\n")
sub(A, "        pixman_image_composite(PIXMAN_OP_SRC, image, NULL, disp_image, 0, 0, 0, 0, 0, 0, genpipe->state.dest_width,\n",
       "        pixman_image_composite((ivm_adp_drawn++ && !getenv(\"IVM_ADP_SRC\")) ? PIXMAN_OP_OVER : PIXMAN_OP_SRC, image, NULL, disp_image, 0, 0, 0, 0, 0, 0, genpipe->state.dest_width,\n")
sub(A, "    for (i = 0; i < ADP_V4_GP_COUNT; ++i) { adp_v4_gp_draw(&adp->genpipe[i], &adp->dma_as, disp_image, adp->console); }\n",
       "    ivm_adp_drawn = 0;\n"
       "    {\n        static int ivm_adp_rev = -1, ivm_adp_log = -1;\n"
       "        if (ivm_adp_rev < 0) { ivm_adp_rev = getenv(\"IVM_ADP_REV\") != NULL; const char* e = getenv(\"IVM_ADP_LOG\"); ivm_adp_log = e ? atoi(e) : 0; }\n"
       "        if (ivm_adp_log > 0 && REG_FIELD_EX32(adp->genpipe[1].state.config_control, GP_CONFIG_CONTROL, ENABLED)) {\n"
       "            ivm_adp_log--;\n"
       "            for (i = 0; i < ADP_V4_GP_COUNT; ++i) {\n"
       "                ADPV4GenPipeState* s = &adp->genpipe[i].state;\n"
       "                fprintf(stderr, \"[ivm-adp] gp%d ctl=0x%x fmt=0x%x src %ux%u dst %ux%u stride %u start 0x%x\\n\", i, s->config_control, s->pixel_format,\n"
       "                        s->src_width, s->src_height, s->dest_width, s->dest_height, s->stride, s->data_start);\n"
       "            }\n"
       "            fprintf(stderr, \"[ivm-adp] blend l0=0x%x l1=0x%x\\n\", adp->blend_unit.layer_config[0], adp->blend_unit.layer_config[1]);\n"
       "        }\n"
       "        for (i = 0; i < ADP_V4_GP_COUNT; ++i) {\n"
       "            int j = ivm_adp_rev ? ADP_V4_GP_COUNT - 1 - i : i;\n"
       "            adp_v4_gp_draw(&adp->genpipe[j], &adp->dma_as, disp_image, adp->console);\n"
       "        }\n    }\n")

# s39 isp64: PW20_P420 still surfaces (see scaler_p10.c). Inferno rejected the format (layout NONE) -> every still
# scaler job (still -> 2212x1660 / 1104x828 / 4032x3024 crop / BGRA thumbs) left zeros (green thumb, black photo).
_P10 = (pathlib.Path(__file__).resolve().parent / "scaler_p10.c").read_text()
sub(S, "static uint32_t ivm_msr_shadow[0x200];", _P10 + "static uint32_t ivm_msr_shadow[0x200];")
sub(S, "        case APPLE_SCALER_FORMAT_YUV_420  : return SCALER_LAYOUT_BIPLANAR_420;\n",
       "        case APPLE_SCALER_FORMAT_YUV_420  :\n        case APPLE_SCALER_FORMAT_PW20_P420: return SCALER_LAYOUT_BIPLANAR_420;\n")
# load
sub(S, "    apple_scaler_image_init(image, apple_scaler_layout_kind(layout), surface->width, surface->height);\n\n"
       "    if (apple_scaler_layout_is_biplanar(layout)) {\n",
       "    apple_scaler_image_init(image, apple_scaler_layout_kind(layout), surface->width, surface->height);\n\n"
       "    if (surface->format == APPLE_SCALER_FORMAT_PW20_P420) {\n"
       "        uint32_t cw, ch;\n        uint8_t* plane1;\n"
       "        ivm_p10_rows(as, surface->base[LUMA], surface->stride[LUMA], surface->width, surface->height, image->plane[0], image->stride[0], false, 0);\n"
       "        apple_scaler_chroma_dims(layout, surface->width, surface->height, &cw, &ch);\n"
       "        plane1 = g_malloc((size_t)cw * 2 * ch);\n"
       "        ivm_p10_rows(as, surface->base[CHROMA], surface->stride[CHROMA], cw * 2, ch, plane1, cw * 2, false, 0);\n"
       "        apple_scaler_chroma_split(image, plane1, (int)(cw * 2));\n"
       "        g_free(plane1);\n        return true;\n    }\n"
       "    if (apple_scaler_layout_is_biplanar(layout)) {\n")
# store
sub(S, "    uint32_t          row_bytes = image->width * apple_scaler_luma_bpp(surface->layout, surface->depth);\n"
       "    uint8_t*          staging;\n    int               ret;\n\n"
       "    if (apple_scaler_layout_is_biplanar(layout)) {\n",
       "    uint32_t          row_bytes = image->width * apple_scaler_luma_bpp(surface->layout, surface->depth);\n"
       "    uint8_t*          staging;\n    int               ret;\n\n"
       "    if (surface->format == APPLE_SCALER_FORMAT_PW20_P420) {\n"
       "        uint32_t cw, ch;\n        uint8_t* plane1;\n"
       "        ivm_p10_rows(as, surface->base[LUMA], surface->stride[LUMA], image->width, image->height, image->plane[0], image->stride[0], true, 0);\n"
       "        apple_scaler_chroma_dims(layout, image->width, image->height, &cw, &ch);\n"
       "        plane1 = g_malloc((size_t)cw * 2 * ch);\n"
       "        apple_scaler_chroma_merge(image, plane1, (int)(cw * 2));\n"
       "        ivm_p10_rows(as, surface->base[CHROMA], surface->stride[CHROMA], cw * 2, ch, plane1, cw * 2, true, 128);\n"
       "        g_free(plane1);\n        return true;\n    }\n"
       "    if (apple_scaler_layout_is_biplanar(layout)) {\n")
# blit (identity copy): packed row bytes
sub(S, "    uint32_t row_bytes = src->width * apple_scaler_luma_bpp(src->layout, src->depth);\n    uint8_t* buf;\n\n"
       "    buf = g_malloc((size_t)row_bytes * src->height);\n",
       "    uint32_t row_bytes = src->format == APPLE_SCALER_FORMAT_PW20_P420 ? ivm_p10_rb(src->width) : src->width * apple_scaler_luma_bpp(src->layout, src->depth);\n    uint8_t* buf;\n\n"
       "    buf = g_malloc((size_t)row_bytes * src->height);\n")
sub(S, "        buf = g_malloc((size_t)cw * 2 * ch);\n"
       "        apple_scaler_dma_rows(as, src->base[CHROMA], src->stride[CHROMA], cw * 2, ch, buf, false);\n"
       "        apple_scaler_dma_rows(as, dst->base[CHROMA], dst->stride[CHROMA], cw * 2, ch, buf, true);\n",
       "        uint32_t crb = src->format == APPLE_SCALER_FORMAT_PW20_P420 ? ivm_p10_rb(cw * 2) : cw * 2;\n"
       "        buf = g_malloc((size_t)crb * ch);\n"
       "        apple_scaler_dma_rows(as, src->base[CHROMA], src->stride[CHROMA], crb, ch, buf, false);\n"
       "        apple_scaler_dma_rows(as, dst->base[CHROMA], dst->stride[CHROMA], crb, ch, buf, true);\n")
print("ispstub: p10 ok")

# s40: scaler job cost (runs synchronously in the vCPU MMIO write with the BQL held) -> "[ivm-msr] cost" every 300 jobs
sub(S, "    if (src_ok && dst_ok) { apple_scaler_process(scaler, &src, &dst); }\n",
       "    if (src_ok && dst_ok) {\n"
       "        static int64_t ivm_msr_tsum, ivm_msr_tmax; static uint32_t ivm_msr_tn;\n"
       "        int64_t ivm_t0 = g_get_monotonic_time();\n"
       "        apple_scaler_process(scaler, &src, &dst);\n"
       "        int64_t ivm_d = g_get_monotonic_time() - ivm_t0;\n"
       "        ivm_msr_tsum += ivm_d; ivm_msr_tmax = MAX(ivm_msr_tmax, ivm_d);\n"
       "        if (++ivm_msr_tn == 300) {\n"
       "            fprintf(stderr, \"[ivm-msr] cost: avg %lld us max %lld us per job (300 jobs)\\n\", (long long)(ivm_msr_tsum / 300), (long long)ivm_msr_tmax);\n"
       "            ivm_msr_tsum = ivm_msr_tmax = 0; ivm_msr_tn = 0;\n"
       "        }\n"
       "    }\n")
print("ispstub: msr cost ok")
