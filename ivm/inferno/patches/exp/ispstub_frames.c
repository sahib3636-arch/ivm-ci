#include "qemu/timer.h"
#include <sys/mman.h>
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
static uint32_t   ivm_isp_poolid[IVM_ISP_NPOOL];  /* slot -> firmware pool id (+1, 0 = free) */
/* output geometry from CH_OUTPUT_CONFIG_SET-like commands: 0x0b01 primary (pool 3), 0x0b09 secondary (pool 6):
 * {.., +0xc w, +0x10 h, .., +0x1c stride0, +0x20 stride1} */
static uint32_t   ivm_isp_out_w[8], ivm_isp_out_h[8], ivm_isp_out_s0[8], ivm_isp_out_s1[8];

static int ivm_isp_pool_slot(uint32_t id)
{
    int i;
    for (i = 0; i < IVM_ISP_NPOOL; i++) {
        if (ivm_isp_poolid[i] == id + 1) {
            return i;
        }
    }
    for (i = 0; i < IVM_ISP_NPOOL; i++) {
        if (!ivm_isp_poolid[i]) {
            ivm_isp_poolid[i] = id + 1;
            return i;
        }
    }
    return -1;
}

static void ivm_isp_out_config(uint32_t idx, const uint8_t* pk, uint32_t len)
{
    if (idx < 8 && len >= 0x24) {
        ivm_isp_out_w[idx]  = ldl_le_p(pk + 0xc);
        ivm_isp_out_h[idx]  = ldl_le_p(pk + 0x10);
        ivm_isp_out_s0[idx] = ldl_le_p(pk + 0x1c);
        ivm_isp_out_s1[idx] = ldl_le_p(pk + 0x20);
        fprintf(stderr, "[ivm-isp] fw: output %u = %ux%u strides %u/%u w14=%08x w18=%08x\n", idx, ivm_isp_out_w[idx], ivm_isp_out_h[idx],
                ivm_isp_out_s0[idx], ivm_isp_out_s1[idx], ldl_le_p(pk + 0x14), ldl_le_p(pk + 0x18));
    }
}
static uint32_t   ivm_isp_sm_addr, ivm_isp_sm_state; /* 0 none, 1 requested, 2 ready */
static uint32_t   ivm_isp_t2h_slot, ivm_isp_frames;
static uint32_t   ivm_isp_p0n;      /* s40 4.0.41: primary-output fill phase, reset on every stream start */
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
        {
            int sl = ivm_isp_pool_slot(ldl_le_p(b.e + 0x24) & 0xfffffff);
            if (sl < 0 || ivm_isp_bufn[sl] >= IVM_ISP_MAXBUF) {
                continue;
            }
            pool = (uint32_t)sl;
        }
        if (ivm_isp_frames < 2 || ivm_isp_bufn[pool] == 0) {
            fprintf(stderr, "[ivm-isp] fw: h2t slot=%u pool=%u iova=%08x/%08x/%08x len=%08x/%08x/%08x/%08x f20=%x tag=%" PRIx64 "\n",
                    pool, ldl_le_p(b.e + 0x24) & 0xfffffff, ldl_le_p(b.e), ldl_le_p(b.e + 4), ldl_le_p(b.e + 8), ldl_le_p(b.e + 0x10),
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

/* ---- camera feed (s39 isp48): IVM_ISP_FEED=<file> shared with the Android app (same uid) ----
 * layout (LE): +0 'IVMC' magic, +4 version 1, +8 engine: wanted camera (0 = none, chan+1), +12 engine heartbeat,
 * +16 app seq (seqlock: odd while writing), +20 w, +24 h, +28 flags (bit0 mirror x), +32 app ms timestamp (u64),
 * +64 NV12 frame: Y w*h then interleaved CbCr (w/2*h/2*2), full range.  Max 1920x1440.
 * The engine maps the file, publishes which channel iOS streams, and samples the newest frame (nearest scale). */
#define IVM_FEED_HDR  64u
#define IVM_FEED_MAXW 1920u
#define IVM_FEED_MAXH 1440u
#define IVM_FEED_SIZE (IVM_FEED_HDR + IVM_FEED_MAXW * IVM_FEED_MAXH * 3u / 2u)
static uint32_t ivm_isp_cur_chan;
static uint8_t* ivm_feed;
static int      ivm_feed_state;   /* 0 untried, 1 mapped, -1 off */
static uint8_t* ivm_feed_copy;    /* stable snapshot of the newest frame */
static uint32_t ivm_feed_cw, ivm_feed_ch, ivm_feed_cseq, ivm_feed_cflags;

static void ivm_feed_open(void)
{
    const char* path = getenv("IVM_ISP_FEED");
    ivm_feed_state = -1;
    if (!path || !*path) {
        return;
    }
    int fd = open(path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        fprintf(stderr, "[ivm-isp] feed: open %s failed: %s\n", path, strerror(errno));
        return;
    }
    if (ftruncate(fd, IVM_FEED_SIZE) != 0) {
        fprintf(stderr, "[ivm-isp] feed: ftruncate failed: %s\n", strerror(errno));
        close(fd);
        return;
    }
    void* m = mmap(NULL, IVM_FEED_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) {
        fprintf(stderr, "[ivm-isp] feed: mmap failed: %s\n", strerror(errno));
        return;
    }
    ivm_feed = m;
    if (ldl_le_p(ivm_feed) != 0x434d5649) {
        memset(ivm_feed, 0, IVM_FEED_HDR);
        stl_le_p(ivm_feed + 4, 1);
        stl_le_p(ivm_feed, 0x434d5649);
    }
    ivm_feed_state = 1;
    fprintf(stderr, "[ivm-isp] feed: mapped %s (%u bytes)\n", path, IVM_FEED_SIZE);
    if (getenv("IVM_ISP_FEED_TEST")) {
        /* act as the app once: 640x480 frame, concentric rings + quadrant colours, so the path is testable in CI */
        uint32_t w = 640, h = 480, x, y;
        uint8_t* Y = ivm_feed + IVM_FEED_HDR, *UV = Y + w * h;
        stl_le_p(ivm_feed + 16, 1);
        for (y = 0; y < h; y++) {
            for (x = 0; x < w; x++) {
                int dx = (int)x - 320, dy = (int)y - 240;
                Y[y * w + x] = (uint8_t)(((dx * dx + dy * dy) / 400) & 1 ? 230 : 40);
            }
        }
        for (y = 0; y < h / 2; y++) {
            for (x = 0; x < w / 2; x++) {
                UV[y * w + 2 * x]     = x < w / 4 ? 60 : 200;
                UV[y * w + 2 * x + 1] = y < h / 4 ? 200 : 60;
            }
        }
        stl_le_p(ivm_feed + 20, w);
        stl_le_p(ivm_feed + 24, h);
        stl_le_p(ivm_feed + 28, 0);
        smp_wmb();
        stl_le_p(ivm_feed + 16, 2);
        fprintf(stderr, "[ivm-isp] feed: test frame written\n");
    }
}

/* publish stream state; called on stream on/off and every frame */
static void ivm_feed_publish(bool on)
{
    if (ivm_feed_state == 0) {
        ivm_feed_open();
    }
    if (ivm_feed_state != 1) {
        return;
    }
    qatomic_set((uint32_t*)(ivm_feed + 8), on ? ivm_isp_cur_chan + 1 : 0);
    qatomic_set((uint32_t*)(ivm_feed + 12), qatomic_read((uint32_t*)(ivm_feed + 12)) + 1);
}

/* take a consistent snapshot of the newest app frame (once per frame tick); false = no usable frame */
static bool ivm_feed_snapshot(void)
{
    uint32_t s1, s2, w, h;
    int      tries;
    if (ivm_feed_state != 1) {
        return false;
    }
    for (tries = 0; tries < 3; tries++) {
        s1 = qatomic_load_acquire((uint32_t*)(ivm_feed + 16));
        if (s1 == 0 || (s1 & 1)) {
            continue;
        }
        if (s1 == ivm_feed_cseq && ivm_feed_copy) {
            return true;
        }
        w = ldl_le_p(ivm_feed + 20);
        h = ldl_le_p(ivm_feed + 24);
        if (w < 16 || h < 16 || w > IVM_FEED_MAXW || h > IVM_FEED_MAXH || (w & 1) || (h & 1)) {
            return false;
        }
        if (!ivm_feed_copy) {
            ivm_feed_copy = g_malloc(IVM_FEED_MAXW * IVM_FEED_MAXH * 3u / 2u);
        }
        memcpy(ivm_feed_copy, ivm_feed + IVM_FEED_HDR, (size_t)w * h * 3 / 2);
        smp_rmb();
        s2 = qatomic_read((uint32_t*)(ivm_feed + 16));
        if (s1 == s2) {
            ivm_feed_cw = w; ivm_feed_ch = h; ivm_feed_cseq = s1;
            ivm_feed_cflags = ldl_le_p(ivm_feed + 28);
            return true;
        }
    }
    return ivm_feed_copy && ivm_feed_cseq;
}

/* s40: picture source = phone feed snapshot or the high-res still file.  flags: bit0 mirror x, bit1 flip y
 * (bit0|bit1 = 180 degrees: S24U front sensor is mounted at 270 vs 90 for the back one), bit2 "iPhone look"
 * tone/colour tables. */
typedef struct {
    const uint8_t* p;
    uint32_t       w, h, flags;
} IvmSrc;
static uint8_t ivm_lut_id[256], ivm_lut_y[256], ivm_lut_u[256], ivm_lut_v[256];
static void    ivm_lut_init(void)
{
    static bool done;
    int         i;
    if (done) {
        return;
    }
    done = true;
    for (i = 0; i < 256; i++) {
        double x = i / 255.0, y = x + 0.10 * x * (1.0 - x) * (1.0 - x) * 1.6;   /* lift shadows / low mids (no libm) */
        if (y > 0.82) {
            y = 0.82 + (y - 0.82) * 0.9 + 0.018 * (y - 0.82) / 0.18;   /* softer highlight roll-off, 1 -> 1 */
        }
        double c = (i - 128) * 0.93 + 128;                              /* slightly less saturated than Samsung */
        ivm_lut_id[i] = (uint8_t)i;
        ivm_lut_y[i]  = (uint8_t)MIN(255, MAX(0, (int)(y * 255.0 + 0.5)));
        ivm_lut_u[i]  = (uint8_t)MIN(255, MAX(0, (int)(c - 2.0 + 0.5)));  /* warmer: less blue */
        ivm_lut_v[i]  = (uint8_t)MIN(255, MAX(0, (int)(c + 2.0 + 0.5)));  /* warmer: more red */
    }
}
static IvmSrc ivm_src_feed(void) { return (IvmSrc){ ivm_feed_copy, ivm_feed_cw, ivm_feed_ch, ivm_feed_cflags }; }

/* centre-crop + nearest map of [src] into w x h: fills xm[] (source x per output x) and the crop rows */
static void ivm_src_map(const IvmSrc* src, uint32_t w, uint32_t h, uint32_t* xm, uint32_t* cy, uint32_t* chh)
{
    uint32_t sw = src->w, sh = src->h, cx = 0, cw = sw, x;
    *cy = 0; *chh = sh;
    if ((uint64_t)sw * h > (uint64_t)sh * w) {
        cw = (uint32_t)((uint64_t)sh * w / h) & ~1u; cx = ((sw - cw) / 2) & ~1u;
    } else {
        *chh = (uint32_t)((uint64_t)sw * h / w) & ~1u; *cy = ((sh - *chh) / 2) & ~1u;
    }
    for (x = 0; x < w; x++) {
        uint32_t sx = cx + (uint32_t)((uint64_t)x * cw / w);
        xm[x] = (src->flags & 1) ? (sw - 1 - sx) : sx;
    }
}
static inline uint32_t ivm_src_row(const IvmSrc* src, uint32_t cy, uint32_t chh, uint32_t y, uint32_t h)
{
    uint32_t r = cy + (uint32_t)((uint64_t)y * chh / h);
    return (src->flags & 2) ? src->h - 1 - r : r;
}

/* nearest-neighbour scale of [src] into an 8-bit 420 bi-planar ISP buffer */
static void ivm_src_fill8(const IvmSrc* src, uint32_t y0, uint32_t y1, uint32_t w, uint32_t h, uint32_t s0, uint32_t s1)
{
    static uint8_t*  row;
    static uint32_t* xm;
    uint32_t         sw = src->w, sh = src->h, cy, chh, x, y, last = UINT32_MAX;
    const uint8_t *  ly, *lu, *lv;
    ivm_lut_init();
    ly = (src->flags & 4) ? ivm_lut_y : ivm_lut_id;
    lu = (src->flags & 4) ? ivm_lut_u : ivm_lut_id;
    lv = (src->flags & 4) ? ivm_lut_v : ivm_lut_id;
    if (!row) {
        row = g_malloc(8192);
        xm  = g_malloc(8192 * sizeof(uint32_t));
    }
    /* s40: map the plane once and write the rows straight into guest RAM (the old path issued one
     * address_space_write per row = one DART page-table walk each).  IVM_ISP_MAP=0 restores it. */
    {
        static int  ivm_isp_map = -1;
        hwaddr      want, plen;
        uint8_t*    dst;
        if (ivm_isp_map < 0) { const char* e = getenv("IVM_ISP_MAP"); ivm_isp_map = e ? atoi(e) : 1; }
        want = (hwaddr)s0 * (h - 1) + w;
        plen = want;
        dst  = ivm_isp_map > 0 ? ivm_isp_staging(want) : NULL;
        if (dst) {
            plen = want;
            for (y = 0; y < h; y++) {
                uint32_t r = ivm_src_row(src, cy, chh, y, h);
                if (r == last) {
                    memcpy(dst + (size_t)y * s0, dst + (size_t)(y - 1) * s0, w);
                    continue;
                }
                {
                    const uint8_t* sp = src->p + (size_t)r * sw;
                    uint8_t*       dp = dst + (size_t)y * s0;
                    for (x = 0; x < w; x++) { dp[x] = ly[sp[xm[x]]]; }
                }
                last = r;
            }
            address_space_write(&ivm_isp_dma_as, y0, MEMTXATTRS_UNSPECIFIED, dst, want);
        }
        else {
            for (y = 0; y < h; y++) {
                uint32_t r = ivm_src_row(src, cy, chh, y, h);
                if (r != last) {   /* upscaling repeats source rows: gather once */
                    const uint8_t* sp = src->p + (size_t)r * sw;
                    for (x = 0; x < w; x++) {
                        row[x] = ly[sp[xm[x]]];
                    }
                    last = r;
                }
                address_space_write(&ivm_isp_dma_as, y0 + y * s0, MEMTXATTRS_UNSPECIFIED, row, w);
            }
        }
    }
    if (!y1) {
        return;
    }
    {
        const uint8_t* uvb = src->p + (size_t)sw * sh;
        static int     ivm_isp_mapc = -1;
        hwaddr         want, plen;
        uint8_t*       dst;
        uint32_t       wb = w & ~1u;
        if (ivm_isp_mapc < 0) { const char* e = getenv("IVM_ISP_MAP"); ivm_isp_mapc = e ? atoi(e) : 1; }
        last = UINT32_MAX;
        want = (hwaddr)s1 * (h / 2 - 1) + wb;
        plen = want;
        dst  = ivm_isp_mapc > 0 ? ivm_isp_staging(want) : NULL;
        if (dst) {
            plen = want;
            for (y = 0; y < h / 2; y++) {
                uint32_t r = ivm_src_row(src, cy, chh, y * 2, h) / 2;
                if (r == last) {
                    memcpy(dst + (size_t)y * s1, dst + (size_t)(y - 1) * s1, wb);
                    continue;
                }
                {
                    const uint8_t* sp = uvb + (size_t)r * sw;
                    uint8_t*       dp = dst + (size_t)y * s1;
                    for (x = 0; x + 1 < w; x += 2) {
                        uint32_t sx = xm[x] & ~1u;
                        dp[x]     = lu[sp[sx]];
                        dp[x + 1] = lv[sp[sx + 1]];
                    }
                }
                last = r;
            }
            address_space_write(&ivm_isp_dma_as, y1, MEMTXATTRS_UNSPECIFIED, dst, want);
        }
        else {
            for (y = 0; y < h / 2; y++) {
                uint32_t r = ivm_src_row(src, cy, chh, y * 2, h) / 2;
                if (r != last) {
                    const uint8_t* sp = uvb + (size_t)r * sw;
                    for (x = 0; x + 1 < w; x += 2) {
                        uint32_t sx = xm[x] & ~1u;
                        row[x]     = lu[sp[sx]];
                        row[x + 1] = lv[sp[sx + 1]];
                    }
                    last = r;
                }
                address_space_write(&ivm_isp_dma_as, y1 + y * s1, MEMTXATTRS_UNSPECIFIED, row, wb);
            }
        }
    }
}
static void ivm_feed_fill(uint32_t y0, uint32_t y1, uint32_t w, uint32_t h, uint32_t s0, uint32_t s1)
{
    IvmSrc src = ivm_src_feed();
    ivm_src_fill8(&src, y0, y1, w, h, s0, s1);
}

/* s40: one address_space_write for a whole plane instead of one per row (each device write invalidates the TCG
 * translations of the touched pages -> ~1700 invalidation passes per frame).  IVM_ISP_BATCH=0 restores it. */
static int ivm_isp_batch(void)
{
    static int on = -1;
    if (on < 0) { const char* e = getenv("IVM_ISP_BATCH"); on = e ? atoi(e) : 1; }
    return on;
}
static uint8_t* ivm_isp_staging(size_t need)
{
    static uint8_t* buf;
    static size_t   cap;
    if (cap < need) { g_free(buf); buf = g_malloc0(need); cap = need; }
    return buf;
}

/* synthetic picture into a 420 bi-planar buffer: luma ramp + moving bars, chroma colour bands */
static int ivm_isp_fill_err;
static int ivm_isp_solid[3] = { -2, 0, 0 };   /* IVM_ISP_SOLID=y,u,v: solid test colour (isp42) */
static void ivm_isp_fill_yuv(const IvmIspBuf* b, uint32_t out)
{
    if (ivm_isp_solid[0] == -2) {
        const char* e = getenv("IVM_ISP_SOLID");
        ivm_isp_solid[0] = -1;
        if (e) {
            sscanf(e, "%d,%d,%d", &ivm_isp_solid[0], &ivm_isp_solid[1], &ivm_isp_solid[2]);
        }
    }
    if (ivm_isp_frames < 3) {
        fprintf(stderr, "[ivm-isp] fw: fill out=%u y=%08x uv=%08x %ux%u s=%u/%u\n", out, ldl_le_p(b->e), ldl_le_p(b->e + 4),
                ivm_isp_out_w[out], ivm_isp_out_h[out], ivm_isp_out_s0[out], ivm_isp_out_s1[out]);
    }
    static uint8_t* row;
    uint32_t        w = ivm_isp_out_w[out], h = ivm_isp_out_h[out], s0 = ivm_isp_out_s0[out], s1 = ivm_isp_out_s1[out];
    uint32_t        y0 = ldl_le_p(b->e), y1 = ldl_le_p(b->e + 4), x, y;
    if (!w || !h || w > 8192 || h > 8192 || s0 < w || !y0) {
        return;
    }
    if (ivm_feed_state == 1 && ivm_feed_copy && ivm_feed_cseq) {
        ivm_feed_fill(y0, (y1 && s1 >= w) ? y1 : 0, w, h, s0, s1);
        return;
    }
    if (!row) {
        row = g_malloc(8192);
    }
    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            uint32_t bar = ((x + ivm_isp_frames * 8) / 96) & 1;
            row[x]       = ivm_isp_solid[0] >= 0 ? (uint8_t)ivm_isp_solid[0] : (uint8_t)(40 + (y * 150) / h + (bar ? 30 : 0));
        }
        if (address_space_write(&ivm_isp_dma_as, y0 + y * s0, MEMTXATTRS_UNSPECIFIED, row, w) != MEMTX_OK &&
            ivm_isp_fill_err++ < 8) {
            fprintf(stderr, "[ivm-isp] fw: luma write fail out=%u y=%u addr=%08x\n", out, y, y0 + y * s0);
        }
    }
    if (y1 && s1 >= w) {
        for (y = 0; y < h / 2; y++) {
            for (x = 0; x + 1 < w; x += 2) {
                uint32_t band = (x * 6) / w;           /* 6 colour bands */
                static const uint8_t uv[6][2] = { { 90, 240 }, { 54, 34 }, { 240, 110 }, { 128, 128 },
                                                  { 200, 200 }, { 60, 160 } };
                row[x]     = ivm_isp_solid[0] >= 0 ? (uint8_t)ivm_isp_solid[1] : uv[band][0];
                row[x + 1] = ivm_isp_solid[0] >= 0 ? (uint8_t)ivm_isp_solid[2] : uv[band][1];
            }
            MemTxResult r = address_space_write(&ivm_isp_dma_as, y1 + y * s1, MEMTXATTRS_UNSPECIFIED, row, w & ~1u);
            if (r != MEMTX_OK && ivm_isp_fill_err++ < 8) {
                fprintf(stderr, "[ivm-isp] fw: chroma write fail out=%u y=%u addr=%08x r=%d\n", out, y, y1 + y * s1, r);
            }
        }
    }
}

/* Metadata buffer layout (H10ISP H10ISPFrameMetadata ctor + ProcessFrameMetadata, isp40):
 *   +0x0c u32 frame number - the receiver expects last+1 (else msg 3/5 -> kFigCaptureStreamNotification_
 *         Discontinuity, DiscontinuityReason; every frame was dropped by BWMultiStreamCameraSourceNode)
 *   +0x10 u32 number of sections, +0x14.. u32 section offsets (from buffer start); section 0 = sCIspMetaData
 *   sCIspMetaData +0x30 u32 frame rate 8.8 (used for the gap duration) */
static uint32_t ivm_isp_meta_fn[IVM_ISP_NPOOL];
static void ivm_isp_fill_meta(const IvmIspBuf* b, uint32_t pool)
{
    uint8_t  hdr[0x40 + 0x200];
    uint32_t a = ldl_le_p(b->e);
    if (!a || getenv("IVM_ISP_NOMETA")) {
        return;
    }
    memset(hdr, 0, sizeof(hdr));
    stl_le_p(hdr + 0x0c, ++ivm_isp_meta_fn[pool]);
    stl_le_p(hdr + 0x10, 1);
    stl_le_p(hdr + 0x14, 0x40);
    stl_le_p(hdr + 0x40 + 0x30, 15 << 8);
    address_space_write(&ivm_isp_dma_as, a, MEMTXATTRS_UNSPECIFIED, hdr, sizeof(hdr));
}

/* s39 isp62: still surface from 0x0b07 is 4224x3168 stride 5632 = w*4/3 -> 10-bit packed bi-planar
 * (3 samples per LE u32, bits 0-9/10-19/20-29). Source = phone feed (8-bit NV12) or the test ramp. */
static IvmSrc ivm_still_src;   /* s40: valid (p != NULL) while a high-res app still is ready for the next fill */
static void ivm_isp_fill_p10(const IvmIspBuf* b, uint32_t w, uint32_t h, uint32_t s0, uint32_t s1)
{
    uint32_t y0 = ldl_le_p(b->e), y1 = ldl_le_p(b->e + 4), x, y, n, cy = 0, chh = 1, last;
    bool     feed = ivm_feed_state == 1 && ivm_feed_copy && ivm_feed_cseq;
    IvmSrc   src  = ivm_still_src.p ? ivm_still_src : ivm_src_feed();
    if (!w || !h || w > 8192 || h > 8192 || !y0 || s0 > 16384) {
        return;
    }
    if (!ivm_still_src.p && !feed) {
        src = (IvmSrc){ NULL, 1, 1, 0 };
    }
    fprintf(stderr, "[ivm-isp] fw: still p10 %ux%u s=%u/%u from %s %ux%u flags %x\n", w, h, s0, s1,
            ivm_still_src.p ? "hires" : (src.p ? "feed" : "pattern"), src.w, src.h, src.flags);
    ivm_lut_init();
    const uint8_t* ly = (src.flags & 4) ? ivm_lut_y : ivm_lut_id;
    const uint8_t* lu = (src.flags & 4) ? ivm_lut_u : ivm_lut_id;
    const uint8_t* lv = (src.flags & 4) ? ivm_lut_v : ivm_lut_id;
    uint32_t* xm  = g_malloc((w + 3) * sizeof(uint32_t));
    uint16_t* smp = g_malloc((w + 3) * sizeof(uint16_t));
    uint8_t*  row = g_malloc(s0 > s1 ? s0 : (s1 ? s1 : s0));
    if (src.p) {
        ivm_src_map(&src, w, h, xm, &cy, &chh);
    }
    uint32_t words = (w + 2) / 3;
    last = UINT32_MAX;
    for (y = 0; y < h; y++) {
        uint32_t r = src.p ? ivm_src_row(&src, cy, chh, y, h) : y;
        if (r != last) {
            const uint8_t* sp = src.p ? src.p + (size_t)r * src.w : NULL;
            for (x = 0; x < w; x++) {
                smp[x] = (uint16_t)((sp ? ly[sp[xm[x]]] : (uint8_t)(40 + (y * 150) / h + (((x / 96) & 1) ? 30 : 0))) << 2);
            }
            smp[w] = smp[w + 1] = smp[w + 2] = 0;
            for (n = 0; n < words && n * 4 + 4 <= s0; n++) {
                stl_le_p(row + n * 4, smp[n * 3] | (smp[n * 3 + 1] << 10) | ((uint32_t)smp[n * 3 + 2] << 20));
            }
            last = r;
        }
        address_space_write(&ivm_isp_dma_as, y0 + y * s0, MEMTXATTRS_UNSPECIFIED, row, words * 4 <= s0 ? words * 4 : s0 & ~3u);
    }
    if (y1 && s1) {
        const uint8_t* uvb = src.p ? src.p + (size_t)src.w * src.h : NULL;
        last = UINT32_MAX;
        for (y = 0; y < h / 2; y++) {
            uint32_t r = src.p ? ivm_src_row(&src, cy, chh, y * 2, h) / 2 : y;
            if (r != last) {
                const uint8_t* sp = uvb ? uvb + (size_t)r * src.w : NULL;
                for (x = 0; x + 1 < w; x += 2) {
                    uint32_t sx = sp ? xm[x] & ~1u : 0, band = (x * 6) / w;
                    static const uint8_t uv[6][2] = { { 90, 240 }, { 54, 34 }, { 240, 110 }, { 128, 128 }, { 200, 200 }, { 60, 160 } };
                    smp[x]     = (uint16_t)((sp ? lu[sp[sx]] : uv[band][0]) << 2);
                    smp[x + 1] = (uint16_t)((sp ? lv[sp[sx + 1]] : uv[band][1]) << 2);
                }
                smp[w] = smp[w + 1] = smp[w + 2] = 512;
                for (n = 0; n < words && n * 4 + 4 <= s1; n++) {
                    stl_le_p(row + n * 4, smp[n * 3] | (smp[n * 3 + 1] << 10) | ((uint32_t)smp[n * 3 + 2] << 20));
                }
                last = r;
            }
            address_space_write(&ivm_isp_dma_as, y1 + y * s1, MEMTXATTRS_UNSPECIFIED, row, words * 4 <= s1 ? words * 4 : s1 & ~3u);
        }
    }
    g_free(xm); g_free(smp); g_free(row);
}

static void ivm_isp_fill_still(const IvmIspBuf* b)
{
    const char* e = getenv("IVM_ISP_STILLWH");
    unsigned    w = 0, h = 0, st = 0;
    fprintf(stderr, "[ivm-isp] fw: still buf iova=%08x/%08x/%08x len=%08x/%08x f20=%x\n", ldl_le_p(b->e),
            ldl_le_p(b->e + 4), ldl_le_p(b->e + 8), ldl_le_p(b->e + 0x10), ldl_le_p(b->e + 0x14), ldl_le_p(b->e + 0x20));
    if (e && sscanf(e, "%u,%u,%u", &w, &h, &st) == 3 && w && h && st >= w) {
        ivm_isp_out_w[7] = w; ivm_isp_out_h[7] = h; ivm_isp_out_s0[7] = st; ivm_isp_out_s1[7] = st;
        ivm_isp_fill_yuv(b, 7);
    } else if (getenv("IVM_ISP_STILLFILL") && ivm_isp_out_w[2] && ivm_isp_out_s0[2] >= ivm_isp_out_w[2]) {
        uint32_t ow = ivm_isp_out_w[2], os = ivm_isp_out_s0[2];
        if (!getenv("IVM_ISP_STILL8") && ((uint64_t)ow * 4 == (uint64_t)os * 3 || getenv("IVM_ISP_STILL10"))) {
            ivm_isp_fill_p10(b, ow, ivm_isp_out_h[2], os, ivm_isp_out_s1[2]);   /* 3x10-bit per u32 */
        } else {
            ivm_isp_fill_yuv(b, 2);   /* 0x0b07 geometry, 8-bit */
        }
    }
}

/* s40 high-res still handshake with the app (feed header): +40 engine still request counter, +44 app done counter,
 * +60 app capability 'HIRS'.  Still file = IVM_ISP_FEED + ".still": +0 'IVMS', +4 seq (even = stable), +8 w,
 * +12 h, +16 flags, +64 NV12 (max 4096x3072). */
#define IVM_STILL_MAXW 4096u
#define IVM_STILL_MAXH 3072u
#define IVM_STILL_SIZE (64u + IVM_STILL_MAXW * IVM_STILL_MAXH * 3u / 2u)
static uint8_t* ivm_still_map;
static int      ivm_still_wait;
static int64_t  ivm_still_t0;
static uint8_t* ivm_still_open(void);
static void ivm_still_selftest(uint32_t req)   /* IVM_ISP_FEED_TEST=2: act as the app (CI) */
{
    uint8_t* m = ivm_still_open();
    uint32_t w = 4000, h = 3000, x, y;
    if (!m) {
        return;
    }
    stl_le_p(m + 4, 1);
    uint8_t *Y = m + 64, *UV = Y + (size_t)w * h;
    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            Y[(size_t)y * w + x] = (uint8_t)((((x + y) / 125) & 1) ? 200 : 60);   /* diagonal stripes */
        }
    }
    for (y = 0; y < h / 2; y++) {
        for (x = 0; x < w / 2; x++) {
            UV[(size_t)y * w + 2 * x] = y < h / 4 ? 90 : 170; UV[(size_t)y * w + 2 * x + 1] = 128;
        }
    }
    stl_le_p(m + 8, w); stl_le_p(m + 12, h); stl_le_p(m + 16, 4); stl_le_p(m, 0x534d5649);
    smp_wmb();
    stl_le_p(m + 4, 2);
    qatomic_store_release((uint32_t*)(ivm_feed + 44), req);
}
static bool ivm_still_capable(void)
{
    if (ivm_feed_state == 1 && getenv("IVM_ISP_FEED_TEST") && atoi(getenv("IVM_ISP_FEED_TEST")) == 2) {
        stl_le_p(ivm_feed + 60, 0x53524948);
    }
    return ivm_feed_state == 1 && ldl_le_p(ivm_feed + 60) == 0x53524948 && !getenv("IVM_ISP_NOHIRES");
}
static uint8_t* ivm_still_open(void)
{
    if (!ivm_still_map) {
        char path[512];
        snprintf(path, sizeof(path), "%s.still", getenv("IVM_ISP_FEED"));
        int fd = open(path, O_RDWR | O_CREAT, 0600);
        if (fd < 0) {
            return NULL;
        }
        if (ftruncate(fd, IVM_STILL_SIZE) == 0) {
            void* m = mmap(NULL, IVM_STILL_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (m != MAP_FAILED) {
                ivm_still_map = m;
            }
        }
        close(fd);
    }
    return ivm_still_map;
}
/* true = keep the still back this tick (waiting for the app's capture) */
static bool ivm_still_hold(void)
{
    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    if (!ivm_still_capable() || !ivm_still_open()) {
        return false;
    }
    if (!ivm_still_wait) {
        ivm_still_wait = 1;
        ivm_still_t0   = now;
        qatomic_store_release((uint32_t*)(ivm_feed + 40), ldl_le_p(ivm_feed + 40) + 1);
        fprintf(stderr, "[ivm-isp] fw: still -> asking the app for a high-res capture (#%u)\n", ldl_le_p(ivm_feed + 40));
        if (atoi(getenv("IVM_ISP_FEED_TEST") ?: "0") == 2) {
            ivm_still_selftest(ldl_le_p(ivm_feed + 40));
        }
        return true;
    }
    const char* e    = getenv("IVM_ISP_STILLWAIT");
    int64_t     wait = e ? atoi(e) : 2500;
    uint32_t    req = ldl_le_p(ivm_feed + 40), done = qatomic_load_acquire((uint32_t*)(ivm_feed + 44));
    if (done != req && now - ivm_still_t0 < wait) {
        return true;
    }
    ivm_still_wait = 0;
    ivm_still_src  = (IvmSrc){ NULL, 0, 0, 0 };
    if (done == req) {
        uint32_t sq = qatomic_load_acquire((uint32_t*)(ivm_still_map + 4)), w = ldl_le_p(ivm_still_map + 8),
                 h = ldl_le_p(ivm_still_map + 12);
        if (ldl_le_p(ivm_still_map) == 0x534d5649 && !(sq & 1) && w >= 16 && h >= 16 && w <= IVM_STILL_MAXW &&
            h <= IVM_STILL_MAXH && !(w & 1) && !(h & 1)) {
            ivm_still_src = (IvmSrc){ ivm_still_map + 64, w, h, ldl_le_p(ivm_still_map + 16) };
        }
    }
    fprintf(stderr, "[ivm-isp] fw: still: app capture %s after %lld ms\n", ivm_still_src.p ? "ready" : "missing (feed frame)",
            (long long)(now - ivm_still_t0));
    return false;
}

static void ivm_isp_frame_tick(void* opaque)
{
    uint32_t pool, k, n = 0;
    uint8_t  msg[8 + 8 * 0x30];
    if (!ivm_isp_streaming) {
        return;
    }
    {   /* IVM_ISP_FPS (default 15): preview frame rate of the fake ISP */
        static int period = -1;
        if (period < 0) { const char* e = getenv("IVM_ISP_FPS"); int f = e ? atoi(e) : 15; period = 1000 / MAX(5, MIN(30, f)); }
        timer_mod(ivm_isp_ftimer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + period);
    }
    ivm_feed_publish(true);
    ivm_feed_snapshot();
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
    /* s39 still capture (isp52): the kernel queues one pool-5 (still image) buffer per shot.  H10ISP
     * MyH10ISPFrameReceivedProc treats a frame carrying the still buffer as a still frame and requires
     * YUV + META with the regular preview metadata absent ("Didn't get YUV+META buffers" otherwise), so the
     * still goes out alone in its own T2H message together with the pools in IVM_ISP_STILLSET (hex mask of
     * fw pool ids; default pool 8). */
    {
        int      ss = -1;
        uint32_t i, mask;
        for (i = 0; i < IVM_ISP_NPOOL; i++) {
            if (ivm_isp_poolid[i] == 5 + 1 && ivm_isp_bufn[i]) {
                ss = (int)i;
            }
        }
        if (ss >= 0 && ivm_still_hold()) {
            return;   /* preview pauses while the phone takes the real photo (like a shutter) */
        }
        if (ss >= 0) {
            const char* e = getenv("IVM_ISP_STILLSET");
            mask = e ? (uint32_t)strtoul(e, NULL, 16) : (1u << 8);
            for (i = 0; i < IVM_ISP_NPOOL && n < 8; i++) {
                uint32_t id = ivm_isp_poolid[i] - 1;
                IvmIspBuf b;
                if (!ivm_isp_poolid[i] || !ivm_isp_bufn[i] || ((int)i != ss && (id >= 32 || !(mask & (1u << id))))) {
                    continue;
                }
                b = ivm_isp_bufq[i][0];
                memmove(&ivm_isp_bufq[i][0], &ivm_isp_bufq[i][1], (--ivm_isp_bufn[i]) * sizeof(IvmIspBuf));
                if ((int)i == ss) {
                    ivm_isp_fill_still(&b);
                } else if (id == 0 || id == 2 || id == 8) {
                    ivm_isp_fill_meta(&b, i);
                }
                memcpy(msg + 8 + n * 0x30, b.e, 0x30);
                n++;
            }
            ivm_still_src = (IvmSrc){ NULL, 0, 0, 0 };
            fprintf(stderr, "[ivm-isp] fw: still frame (%u bufs, set %x)\n", n, mask);
            goto send;
        }
    }
    int64_t tf0 = g_get_monotonic_time();
    for (pool = 0; pool < IVM_ISP_NPOOL && n < 8; pool++) {
        IvmIspBuf b;
        if (!ivm_isp_bufn[pool]) {
            continue;
        }
        b = ivm_isp_bufq[pool][0];
        memmove(&ivm_isp_bufq[pool][0], &ivm_isp_bufq[pool][1], (--ivm_isp_bufn[pool]) * sizeof(IvmIspBuf));
        if (!getenv("IVM_ISP_NOFILL")) {
            uint32_t id = ivm_isp_poolid[pool] - 1;
            if (id == 3) {
                static int p0every = -1;
                if (p0every < 0) { const char* e = getenv("IVM_ISP_P0EVERY"); p0every = e ? MAX(1, atoi(e)) : 1; }
                /* s40 4.0.41: only thin out an EXTRA big output.  Several modes (Portrait, and the front
                 * camera in some pipelines) configure a single preview: output 0 = 1504x1128 and no output 1.
                 * Thinning that one feeds the guest unfilled (zero = green) buffers ~7 frames out of 8, i.e. a
                 * green screen that flickers at ~2 fps.  When output 1 exists and is smaller, output 0 is the
                 * Live/staging surface and the old behaviour (every Nth frame) is what we want. */
                bool extra = ivm_isp_out_w[1] && ivm_isp_out_h[1] &&
                             (uint64_t)ivm_isp_out_w[0] * ivm_isp_out_h[0] >
                             (uint64_t)ivm_isp_out_w[1] * ivm_isp_out_h[1];
                uint32_t n0 = ivm_isp_p0n++;
                if (!extra || n0 % p0every == 0) {
                    ivm_isp_fill_yuv(&b, 0);
                }
            } else if (id == 6) {
                ivm_isp_fill_yuv(&b, 1);
            } else if (id == 0 || id == 2 || id == 8) {
                ivm_isp_fill_meta(&b, pool);
            }
        }
        memcpy(msg + 8 + n * 0x30, b.e, 0x30);
        n++;
    }
    {   /* s40: preview fill cost (runs on the main loop with the BQL held) */
        static int64_t tsum, tmax; static uint32_t tn;
        int64_t d = g_get_monotonic_time() - tf0;
        tsum += d; tmax = MAX(tmax, d);
        if (++tn == 150) {
            fprintf(stderr, "[ivm-isp] fill: avg %lld us max %lld us per frame (150 frames)\n", (long long)(tsum / tn), (long long)tmax);
            tsum = tmax = 0; tn = 0;
        }
    }
send:
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
    ivm_feed_publish(on);
    if (on) {
        ivm_isp_p0n = 0;   /* the first frame of every stream is always a real one (no green flash) */
    }
    fprintf(stderr, "[ivm-isp] fw: stream %s\n", on ? "ON" : "OFF");
    if (on) {
        ivm_isp_sm_request();
        timer_mod(ivm_isp_ftimer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 33);
    } else {
        timer_del(ivm_isp_ftimer);
    }
}
