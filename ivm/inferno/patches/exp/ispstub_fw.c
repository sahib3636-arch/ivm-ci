/* ---- ivm ispstub: fake ISP firmware, boot handshake (inserted by exp/ispstub.py) ----
 * H10 ISP (version 10), GPIO mailbox block at region0 +0x1ae4100 (GPIO0..GPIO7 = +0x00..+0x1c).
 * AppleH10CamIn::ISP_StartFirmware, preloaded-firmware path (DT isp pre-loaded + segment-ranges):
 *   kext: zero GPIO0..7, write 0x10 to +0x1400044 (release the ISP CPU)
 *   fw:   GPIO0 = number of IPC channels, GPIO1 = IPC queue size - 1, GPIO3 = extra heap size,
 *         GPIO4 = 0 (no unit-test mode), GPIO7 = 0x8042006 (wake)
 *   kext: GPIO0 = boot-args ISP address, GPIO7 = 0xf7fbdff9, reads GPIO7 back expecting 0x8042006
 *   fw:   GPIO0 = ISP address of the channel table (n x 0x100: name[64], type, src, num, iova at 0x4c)
 *   kext: GPIO3 = 0x8042006, polls until GPIO3 == 0
 * ISP addresses are offsets into the consolidated firmware mapping (our carve-out), see ispAddressToHostAddress.
 */
/* v10 (0x1ae4100) or v9 (0x1aa4100) block, chosen by the kext from the ISP version; serve both */
static const uint32_t ivm_isp_gbase[2] = { 0x1ae4100u, 0x1aa4100u };
#define IVM_ISP_GPIO(n)     (gb + 4u * (n))
#define IVM_ISP_CPU_RUN     0x1400044u
#define IVM_ISP_TABLE       0x100000u
#define IVM_ISP_RING0       0x110000u
#define IVM_ISP_RING_STRIDE 0x10000u

typedef struct {
    const char* name;
    uint32_t    type, src, num;
} IvmIspChan;

/* Asahi apple-isp naming: type 0 = command (host to fw), 1 = reply, 2 = report (fw to host) */
static const IvmIspChan ivm_isp_chans[] = {
    { "TERMINAL", 2, 0, 16 },
    { "IO", 0, 1, 8 },
    { "DEBUG", 0, 2, 8 },
    { "BUF_H2T", 0, 3, 64 },
    { "BUF_T2H", 1, 3, 64 },
    { "SHAREDMALLOC", 1, 3, 8 },
    { "IO_T2H", 1, 3, 8 },
};

static qemu_irq ivm_isp_irq;      /* AIC line of isp interrupts[0] (kext registers index 0) */
static uint32_t ivm_isp_pend;     /* pending sources: bit (1 << channel src) */
static long     ivm_isp_ncmd;
static AddressSpace ivm_isp_dma_as;   /* ISP view through dart-isp (mapper-isp SID) */
static bool     ivm_isp_dma_ok;

static void ivm_isp_set(uint32_t off, uint32_t val)
{
    g_hash_table_insert(ivm_isp_regs, GUINT_TO_POINTER(off), GUINT_TO_POINTER(val));
}

/* ---- command responses (Asahi isp-cmd.h layouts: u64 opcode word, then payload) ---- */
static void ivm_isp_put32(uint8_t* b, uint32_t len, uint32_t off, uint32_t v)
{
    if (off + 4 <= len) {
        stl_le_p(b + off, v);
    }
}

static void ivm_isp_put16(uint8_t* b, uint32_t len, uint32_t off, uint16_t v)
{
    if (off + 2 <= len) {
        stw_le_p(b + off, v);
    }
}

static void ivm_isp_putstr(uint8_t* b, uint32_t len, uint32_t off, const char* str, uint32_t max)
{
    uint32_t n = strlen(str);
    if (n > max - 1) {
        n = max - 1;
    }
    if (off + n < len) {
        memcpy(b + off, str, n);
    }
}

/* channel -> sensor (platform table, iPhone 11 / sensor-type 0xaf: 0 rear, 2 frnt, 3 firc (Face ID IR), 4 resw) */
static uint16_t ivm_isp_sensor_id(uint32_t ch)
{
    switch (ch) {
    case 0: return 0x0503;   /* back wide */
    case 2: return 0x0330;   /* front */
    case 4: return 0x0372;   /* back super wide */
    default: return 0;       /* 1, 5 absent; 3 (IR) not modelled */
    }
}

static bool ivm_isp_cmd_respond(uint8_t* b, uint32_t len, uint16_t op)
{
    uint32_t ch = len >= 12 ? ldl_le_p(b + 8) : 0;
    switch (op) {
    case 0x0003:   /* CONFIG_GET */
        ivm_isp_put32(b, len, 0x08, 24000000);   /* timestamp_freq */
        ivm_isp_put32(b, len, 0x0c, 6);          /* num_channels (driver max 6) */
        return true;
    case 0x0006:   /* BUILDINFO */
        ivm_isp_putstr(b, len, 0x28, "Oct  4 2026", 0x20);
        ivm_isp_putstr(b, len, 0x48, "ivm-hle-isp 1.0", 0x60);
        return true;
    case 0x010d:   /* CH_INFO_GET */
        if (!ivm_isp_sensor_id(ch)) {
            return false;
        }
        ivm_isp_put32(b, len, 0x0c, 0x7da0001);
        ivm_isp_put32(b, len, 0x10, 0x300ac);
        ivm_isp_put32(b, len, 0x14, 0x40007);
        ivm_isp_put32(b, len, 0x18, 0x5);
        ivm_isp_put32(b, len, 0x1c, 0x1);
        ivm_isp_put32(b, len, 0x20, ivm_isp_sensor_id(ch));
        ivm_isp_put32(b, len, 0x24, 0x7);
        ivm_isp_put32(b, len, 0x28, 0x1);
        ivm_isp_put32(b, len, 0x2c, 0x7);
        ivm_isp_put32(b, len, 0x4c, 0x10000);
        ivm_isp_put32(b, len, 0x50, 0x1);
        ivm_isp_put32(b, len, 0x58, 0x4);
        ivm_isp_put32(b, len, 0x5c, 0x10);
        ivm_isp_put32(b, len, 0x60, 1);          /* num_presets */
        ivm_isp_put32(b, len, 0x68, 0x44c0);
        ivm_isp_put32(b, len, 0x6c, 0x40);
        ivm_isp_put32(b, len, 0x70, 0x1);
        ivm_isp_put32(b, len, 0x74, 0x2);
        ivm_isp_put32(b, len, 0x78, 0x4000);
        ivm_isp_put32(b, len, 0x7c, 0x40);
        ivm_isp_put32(b, len, 0x80, 0x1);
        ivm_isp_put32(b, len, 0x84, 0x4d564900u | ch);   /* sensor SN (8 bytes) */
        ivm_isp_put32(b, len, 0x88, 0x2026);
        ivm_isp_put32(b, len, 0x8c, 0x36);
        ivm_isp_put32(b, len, 0x98, 24000000);
        {
            char sn[20];
            snprintf(sn, sizeof(sn), "IVMCAM%02u0001", ch);
            ivm_isp_putstr(b, len, 0x9e, sn, 18);
        }
        ivm_isp_put32(b, len, 0xb4, 0x8);
        ivm_isp_put32(b, len, 0xc0, 0x4);
        ivm_isp_put32(b, len, 0xdc, 0xff0000);
        ivm_isp_put32(b, len, 0xe0, 0xc00);
        ivm_isp_put32(b, len, 0xe8, 0x1c);
        ivm_isp_put32(b, len, 0xec, 0x640);
        ivm_isp_put32(b, len, 0xf0, 0x4);
        ivm_isp_put32(b, len, 0xf4, 0x4);
        return true;
    case 0x0105:   /* CH_CAMERA_CONFIG_CURRENT_GET */
    case 0x0106: { /* CH_CAMERA_CONFIG_GET */
        uint16_t w = 1920, h = 1440;
        ivm_isp_put16(b, len, 0x10, w);
        ivm_isp_put16(b, len, 0x12, h);
        ivm_isp_put16(b, len, 0x14, w);
        ivm_isp_put16(b, len, 0x16, h);
        ivm_isp_put32(b, len, 0x60, 24000000);   /* sensor_clk */
        ivm_isp_put32(b, len, 0x74, 24000000);   /* timestamp_freq */
        ivm_isp_put32(b, len, 0xc0, w);
        ivm_isp_put32(b, len, 0xc4, h);
        ivm_isp_put32(b, len, 0xd0, w);
        ivm_isp_put32(b, len, 0xd4, h);
        return true;
    }
    default:
        return false;
    }
}

static void ivm_isp_ring_rw(uint32_t ring, uint32_t slot, uint32_t* w0, bool wr)
{
    hwaddr a = ivm_isp_fw_phys + ring + slot * 0x40u;
    if (wr) {
        uint32_t le = cpu_to_le32(*w0);
        address_space_write(&address_space_memory, a, MEMTXATTRS_UNSPECIFIED, &le, 4);
    } else {
        uint32_t le = 0;
        address_space_read(&address_space_memory, a, MEMTXATTRS_UNSPECIFIED, &le, 4);
        *w0 = le32_to_cpu(le);
    }
}

/* IOProcessorChannel slots are 64 B: w0 = ISP address | turn bit0, w1, w2.  Command (type 0) rings: host
 * writes bit0 = 0, fw completes by setting bit0 = 1 (cmd+6 ack stays 0 = success).  Other rings start owned by
 * fw (bit0 = 1).  Completion raises pending bit (1 << src) at +0x1ae0100, host W1C-clears via +0x1ae4a0c. */
static void ivm_isp_doorbell(uint32_t gb, uint32_t bits)
{
    uint32_t i, k, w0, w[3], done = 0;
    for (i = 0; i < ARRAY_SIZE(ivm_isp_chans); i++) {
        uint32_t ring = IVM_ISP_RING0 + i * IVM_ISP_RING_STRIDE;
        if (ivm_isp_chans[i].type != 0 || !((bits >> ivm_isp_chans[i].src) & 1)) {
            continue;
        }
        for (k = 0; k < ivm_isp_chans[i].num; k++) {
            ivm_isp_ring_rw(ring, k, &w0, false);
            if (w0 & 1) {
                continue;
            }
            address_space_read(&address_space_memory, ivm_isp_fw_phys + ring + k * 0x40u, MEMTXATTRS_UNSPECIFIED, w, 12);
            if (ivm_isp_ncmd++ < 2000) {
                uint8_t c[24] = { 0 };
                char hex[64];
                uint32_t n;
                if (ivm_isp_dma_ok) {
                    address_space_read(&ivm_isp_dma_as, le32_to_cpu(w[0]) & ~3u, MEMTXATTRS_UNSPECIFIED, c, sizeof(c));
                }
                for (n = 0; n < sizeof(c); n++) {
                    snprintf(hex + 2 * n, 3, "%02x", c[n]);
                }
                fprintf(stderr, "[ivm-isp] fw: cmd #%ld %s[%u] addr=0x%x len=0x%x op=0x%04x [%s] -> ack\n", ivm_isp_ncmd,
                        ivm_isp_chans[i].name, k, le32_to_cpu(w[0]), le32_to_cpu(w[1]), lduw_le_p(c + 4), hex);
            }
            if (ivm_isp_dma_ok) {
                uint32_t len = le32_to_cpu(w[1]);
                uint32_t a = le32_to_cpu(w[0]) & ~3u;
                if (len >= 8 && len <= 0x1000) {
                    uint8_t* pk = g_malloc0(len);
                    address_space_read(&ivm_isp_dma_as, a, MEMTXATTRS_UNSPECIFIED, pk, len);
                    {   /* first packet of each opcode: full hex dump (<= 0x200 B) */
                        static GHashTable* seen;
                        uint16_t op = lduw_le_p(pk + 4);
                        if (!seen) {
                            seen = g_hash_table_new(g_direct_hash, g_direct_equal);
                        }
                        if (!g_hash_table_contains(seen, GUINT_TO_POINTER((guint)op + 1))) {
                            uint32_t n, m = len < 0x200 ? len : 0x200;
                            GString* gs = g_string_new(NULL);
                            g_hash_table_add(seen, GUINT_TO_POINTER((guint)op + 1));
                            for (n = 0; n < m; n++) {
                                g_string_append_printf(gs, "%02x", pk[n]);
                            }
                            fprintf(stderr, "[ivm-isp] fw: dump op=0x%04x len=0x%x %s\n", op, len, gs->str);
                            g_string_free(gs, TRUE);
                        }
                    }
                    if (ivm_isp_cmd_respond(pk, len, lduw_le_p(pk + 4))) {
                        address_space_write(&ivm_isp_dma_as, a, MEMTXATTRS_UNSPECIFIED, pk, len);
                    }
                    g_free(pk);
                }
            }
            w0 |= 1;
            ivm_isp_ring_rw(ring, k, &w0, true);
            done |= 1u << ivm_isp_chans[i].src;
        }
    }
    if (done && GPOINTER_TO_UINT(g_hash_table_lookup(ivm_isp_regs, GUINT_TO_POINTER(IVM_ISP_GPIO(0)))) == 0xf7fbdff9u) {
        /* ISP_Suspend: GPIO0 = 0xf7fbdff9 + suspend command -> fw parks and answers 0x8042006 */
        ivm_isp_set(IVM_ISP_GPIO(0), 0x8042006);
        fprintf(stderr, "[ivm-isp] fw: suspend -> parked\n");
    }
    if (done) {
        ivm_isp_pend |= done;
        ivm_isp_set(gb - 0x4000u, ivm_isp_pend);
        if (ivm_isp_irq) {
            qemu_irq_raise(ivm_isp_irq);
        }
    }
}

static void ivm_isp_fw_write(hwaddr off, uint64_t val)
{
    uint32_t i, j, gb;
    if (!ivm_isp_fw_phys) {
        return;
    }
    for (j = 0; j < 2; j++) {
    gb = ivm_isp_gbase[j];
    if (off == IVM_ISP_CPU_RUN && (val & 0x10)) {
        uint8_t tbl[0x100];
        for (i = 0; i < ARRAY_SIZE(ivm_isp_chans); i++) {
            memset(tbl, 0, sizeof(tbl));
            memcpy(tbl, ivm_isp_chans[i].name, strlen(ivm_isp_chans[i].name));
            stl_le_p(tbl + 0x40, ivm_isp_chans[i].type);
            stl_le_p(tbl + 0x44, ivm_isp_chans[i].src);
            stl_le_p(tbl + 0x48, ivm_isp_chans[i].num);
            stl_le_p(tbl + 0x4c, IVM_ISP_RING0 + i * IVM_ISP_RING_STRIDE);
            address_space_write(&address_space_memory, ivm_isp_fw_phys + IVM_ISP_TABLE + i * 0x100,
                                MEMTXATTRS_UNSPECIFIED, tbl, sizeof(tbl));
        }
        if (j == 0) {
            uint32_t k, one = 1;
            for (i = 0; i < ARRAY_SIZE(ivm_isp_chans); i++) {
                for (k = 0; ivm_isp_chans[i].type != 0 && k < ivm_isp_chans[i].num; k++) {
                    ivm_isp_ring_rw(IVM_ISP_RING0 + i * IVM_ISP_RING_STRIDE, k, &one, true);
                }
            }
            ivm_isp_pend = 0;
            fprintf(stderr, "[ivm-isp] fw: CPU released -> wake (%u channels)\n", (unsigned)ARRAY_SIZE(ivm_isp_chans));
        }
        ivm_isp_set(IVM_ISP_GPIO(0), ARRAY_SIZE(ivm_isp_chans));
        ivm_isp_set(IVM_ISP_GPIO(1), 0xfff);
        ivm_isp_set(IVM_ISP_GPIO(3), 0);
        ivm_isp_set(IVM_ISP_GPIO(4), 0);
        ivm_isp_set(IVM_ISP_GPIO(7), 0x8042006);
    } else if (off == IVM_ISP_GPIO(7) && (uint32_t)val == 0xf7fbdff9u) {
        gpointer v = g_hash_table_lookup(ivm_isp_regs, GUINT_TO_POINTER(IVM_ISP_GPIO(0)));
        fprintf(stderr, "[ivm-isp] fw: boot args at 0x%x -> channel table at 0x%x\n", GPOINTER_TO_UINT(v), IVM_ISP_TABLE);
        ivm_isp_set(IVM_ISP_GPIO(0), IVM_ISP_TABLE);
        ivm_isp_set(IVM_ISP_GPIO(1), 0);
        ivm_isp_set(IVM_ISP_GPIO(7), 0x8042006);
    } else if (off == gb + 0x900u) {
        ivm_isp_doorbell(gb, (uint32_t)val);
    } else if (off == gb + 0x90cu) {
        ivm_isp_pend &= ~(uint32_t)val;
        ivm_isp_set(gb - 0x4000u, ivm_isp_pend);
        if (!ivm_isp_pend && ivm_isp_irq) {
            qemu_irq_lower(ivm_isp_irq);
        }
    } else if (off == IVM_ISP_GPIO(3) && (uint32_t)val == 0x8042006u) {
        ivm_isp_set(IVM_ISP_GPIO(3), 0);
        fprintf(stderr, "[ivm-isp] fw: channels armed -> firmware running\n");
    }
    }
}

