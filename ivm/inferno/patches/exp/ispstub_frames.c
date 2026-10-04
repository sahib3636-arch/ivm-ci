#include "qemu/timer.h"
/* ---- fake frame delivery (s39, exp/ispstub_frames.c, inlined by ispstub.py into ispstub_fw.c) ----
 * BUF_H2T (host -> fw): msg {u32 type 1, u32 count, count x 0x30 entries: +0 plane iova[4], +0x10 u32[4],
 *   +0x20 u32, +0x24 pool, +0x28 u64 tag}.  Entries are queued per pool.
 * SHAREDMALLOC (fw -> host, parity 0): fw writes slot {w0 = 0, w1 = size, w2 = tag}; the host allocates a
 *   shared-memory surface and answers on the same slot w0 = ISP address | 1, w2 = id
 *   (AppleH10CamIn::processSharedMallocRequest).  Used as the T2H message heap.
 * BUF_T2H (fw -> host, parity 0): slot w0 = ISP address of {u32 type 1, u32 count <= 8, entries} with the
 *   tag echoed (processTargetToHostBufferNotification); the host acks by flipping bit0 back to 1.
 * After CH_START (0x100) a virtual-clock timer returns buffers every frame period with a synthetic picture
 * written through the ISP DART. */
#define IVM_ISP_CH_H2T  3
#define IVM_ISP_CH_T2H  4
#define IVM_ISP_CH_SM   5
#define IVM_ISP_SM_SIZE 0x8000u
#define IVM_ISP_MAXBUF  64
#define IVM_ISP_NPOOL   32

typedef struct {
    uint8_t e[0x30];
} IvmIspBuf;

static IvmIspBuf  ivm_isp_bufq[IVM_ISP_NPOOL][IVM_ISP_MAXBUF];
static uint32_t   ivm_isp_bufn[IVM_ISP_NPOOL];
static uint32_t   ivm_isp_sm_addr, ivm_isp_sm_state; /* 0 none, 1 requested, 2 ready */
static uint32_t   ivm_isp_t2h_slot, ivm_isp_frames;
static bool       ivm_isp_streaming;
static QEMUTimer* ivm_isp_ftimer;

static void ivm_isp_raise(uint32_t src)
{
    ivm_isp_pend |= 1u << src;
    ivm_isp_set(ivm_isp_gbase[0] - 0x4000u, ivm_isp_pend);
    ivm_isp_set(ivm_isp_gbase[1] - 0x4000u, ivm_isp_pend);
    if (ivm_isp_irq) {
        qemu_irq_raise(ivm_isp_irq);
    }
}

static hwaddr ivm_isp_slot_addr(uint32_t ch, uint32_t k)
{
    return ivm_isp_fw_phys + IVM_ISP_RING0 + ch * IVM_ISP_RING_STRIDE + k * 0x40u;
}

static void ivm_isp_slot_write(uint32_t ch, uint32_t k, uint32_t w0, uint32_t w1, uint32_t w2)
{
    uint32_t w[3] = { cpu_to_le32(w0), cpu_to_le32(w1), cpu_to_le32(w2) };
    hwaddr   a    = ivm_isp_slot_addr(ch, k);
    address_space_write(&address_space_memory, a + 4, MEMTXATTRS_UNSPECIFIED, &w[1], 8);
    address_space_write(&address_space_memory, a, MEMTXATTRS_UNSPECIFIED, &w[0], 4);
}

static uint32_t ivm_isp_slot_w0(uint32_t ch, uint32_t k)
{
    uint32_t le = 0;
    address_space_read(&address_space_memory, ivm_isp_slot_addr(ch, k), MEMTXATTRS_UNSPECIFIED, &le, 4);
    return le32_to_cpu(le);
}

/* host gave us buffers */
static void ivm_isp_h2t(uint32_t addr)
{
    uint8_t  hdr[8];
    uint32_t n, i;
    address_space_read(&ivm_isp_dma_as, addr, MEMTXATTRS_UNSPECIFIED, hdr, 8);
    n = ldl_le_p(hdr + 4);
    if (ldl_le_p(hdr) != 1 || n > IVM_ISP_MAXBUF) {
        fprintf(stderr, "[ivm-isp] fw: h2t bad msg type=%u n=%u\n", ldl_le_p(hdr), n);
        return;
    }
    for (i = 0; i < n; i++) {
        IvmIspBuf b;
        uint32_t  pool;
        address_space_read(&ivm_isp_dma_as, addr + 8 + i * 0x30, MEMTXATTRS_UNSPECIFIED, b.e, 0x30);
        pool = ldl_le_p(b.e + 0x24) & 0xfffffff;
        if (pool >= IVM_ISP_NPOOL || ivm_isp_bufn[pool] >= IVM_ISP_MAXBUF) {
            continue;
        }
        if (ivm_isp_frames < 2 || ivm_isp_bufn[pool] == 0) {
            fprintf(stderr, "[ivm-isp] fw: h2t pool=%u iova=%08x/%08x/%08x len=%08x/%08x/%08x/%08x f20=%x tag=%" PRIx64 "\n",
                    pool, ldl_le_p(b.e), ldl_le_p(b.e + 4), ldl_le_p(b.e + 8), ldl_le_p(b.e + 0x10),
                    ldl_le_p(b.e + 0x14), ldl_le_p(b.e + 0x18), ldl_le_p(b.e + 0x1c), ldl_le_p(b.e + 0x20),
                    ldq_le_p(b.e + 0x28));
        }
        ivm_isp_bufq[pool][ivm_isp_bufn[pool]++] = b;
    }
}

static void ivm_isp_sm_request(void)
{
    if (ivm_isp_sm_state) {
        return;
    }
    ivm_isp_sm_state = 1;
    ivm_isp_slot_write(IVM_ISP_CH_SM, 0, 0, IVM_ISP_SM_SIZE, 0x4d564930); /* tag 'IVM0' */
    fprintf(stderr, "[ivm-isp] fw: SHAREDMALLOC request 0x%x\n", IVM_ISP_SM_SIZE);
    ivm_isp_raise(ivm_isp_chans[IVM_ISP_CH_SM].src);
}

/* called on every host doorbell: pick up the SHAREDMALLOC answer */
static void ivm_isp_sm_poll(void)
{
    uint32_t w0;
    if (ivm_isp_sm_state != 1) {
        return;
    }
    w0 = ivm_isp_slot_w0(IVM_ISP_CH_SM, 0);
    if (w0 & 1) {
        ivm_isp_sm_addr  = w0 & ~3u;
        ivm_isp_sm_state = 2;
        fprintf(stderr, "[ivm-isp] fw: SHAREDMALLOC -> ISP addr 0x%x\n", ivm_isp_sm_addr);
    }
}

/* synthetic picture: luma ramp + moving bar, chroma neutral (only within the first `lim` bytes) */
static void ivm_isp_fill(uint32_t iova, uint32_t lim)
{
    static uint8_t* row;
    uint32_t        w = 1504, y, rows, off = 0;
    const char*     e = getenv("IVM_ISP_FILL");
    if (e) {
        lim = (uint32_t)strtoul(e, NULL, 0);
    }
    if (!row) {
        row = g_malloc(4096);
    }
    rows = lim / w;
    for (y = 0; y < rows; y++, off += w) {
        uint32_t x;
        for (x = 0; x < w; x++) {
            uint32_t bar = ((x + ivm_isp_frames * 16) / 64) & 1;
            row[x]       = (uint8_t)(32 + (y * 160 / (rows ? rows : 1)) + (bar ? 40 : 0));
        }
        address_space_write(&ivm_isp_dma_as, iova + off, MEMTXATTRS_UNSPECIFIED, row, w);
    }
}

static void ivm_isp_frame_tick(void* opaque)
{
    uint32_t pool, k, n = 0;
    uint8_t  msg[8 + 8 * 0x30];
    if (!ivm_isp_streaming) {
        return;
    }
    timer_mod(ivm_isp_ftimer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 66);
    if (ivm_isp_sm_state != 2) {
        ivm_isp_sm_poll();
        return;
    }
    /* find a free T2H slot (fw-owned = bit0 set) */
    for (k = 0; k < ivm_isp_chans[IVM_ISP_CH_T2H].num; k++) {
        uint32_t s = (ivm_isp_t2h_slot + k) % ivm_isp_chans[IVM_ISP_CH_T2H].num;
        if (ivm_isp_slot_w0(IVM_ISP_CH_T2H, s) & 1) {
            ivm_isp_t2h_slot = s;
            break;
        }
    }
    if (k == ivm_isp_chans[IVM_ISP_CH_T2H].num) {
        return;
    }
    memset(msg, 0, sizeof(msg));
    for (pool = 0; pool < IVM_ISP_NPOOL && n < 8; pool++) {
        IvmIspBuf b;
        if (!ivm_isp_bufn[pool]) {
            continue;
        }
        b = ivm_isp_bufq[pool][0];
        memmove(&ivm_isp_bufq[pool][0], &ivm_isp_bufq[pool][1], (--ivm_isp_bufn[pool]) * sizeof(IvmIspBuf));
        if (getenv("IVM_ISP_FILL") && pool == (uint32_t)atoi(getenv("IVM_ISP_FILLPOOL") ?: "99")) {
            ivm_isp_fill(ldl_le_p(b.e), 0);
        }
        memcpy(msg + 8 + n * 0x30, b.e, 0x30);
        n++;
    }
    if (!n) {
        return;
    }
    stl_le_p(msg, 1);
    stl_le_p(msg + 4, n);
    {
        uint32_t a = ivm_isp_sm_addr + (ivm_isp_t2h_slot % 32) * 0x200;
        address_space_write(&ivm_isp_dma_as, a, MEMTXATTRS_UNSPECIFIED, msg, 8 + n * 0x30);
        ivm_isp_slot_write(IVM_ISP_CH_T2H, ivm_isp_t2h_slot, a, 8 + n * 0x30, 0);
        if (ivm_isp_frames < 4 || ivm_isp_frames % 100 == 0) {
            fprintf(stderr, "[ivm-isp] fw: frame %u -> T2H slot %u msg 0x%x (%u bufs)\n", ivm_isp_frames,
                    ivm_isp_t2h_slot, a, n);
        }
    }
    ivm_isp_t2h_slot = (ivm_isp_t2h_slot + 1) % ivm_isp_chans[IVM_ISP_CH_T2H].num;
    ivm_isp_frames++;
    ivm_isp_raise(ivm_isp_chans[IVM_ISP_CH_T2H].src);
}

static void ivm_isp_stream(bool on)
{
    if (getenv("IVM_ISP_NOFRAMES")) {
        return;
    }
    if (!ivm_isp_ftimer) {
        ivm_isp_ftimer = timer_new_ms(QEMU_CLOCK_VIRTUAL, ivm_isp_frame_tick, NULL);
    }
    ivm_isp_streaming = on;
    fprintf(stderr, "[ivm-isp] fw: stream %s\n", on ? "ON" : "OFF");
    if (on) {
        ivm_isp_sm_request();
        timer_mod(ivm_isp_ftimer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 33);
    } else {
        timer_del(ivm_isp_ftimer);
    }
}
