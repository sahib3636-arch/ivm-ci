/* ---- iVM userland trace + os_log mirror (exp/ktrace.py, s39) ----
 * IVM_SLIDEPC=<kernel VA of vm_shared_region_slide>: first call's x0 = dyld shared cache slide.
 * IVM_DSC_SLIDE=<hex>: fixed slide (skips detection).
 * IVM_OSLOG=<unslid VA of _os_log_impl>: every enabled os_log call in any process is formatted and printed
 *   as "[oslog] dso=<unslid mach header> <message>" (first IVM_OSLOG_N, default 40000).
 *   IVM_OSLOG_DSO=<hex,...> optional filter on unslid dso (image mach header).
 * IVM_UTRACE=<unslid VA,...>: register dump like ktrace, pc printed unslid. */
extern uint64_t ivm_dsc_slide;
uint64_t ivm_dsc_slide;
static long ivm_oslog_hits, ivm_oslog_max = -1;
static uint64_t ivm_oslog_dso[16];
static int ivm_oslog_ndso;

static void ivm_u_read(CPUARMState* env, uint64_t va, void* buf, size_t len)
{
    memset(buf, 0, len);
    if (va) {
        cpu_memory_rw_debug(env_cpu(env), va, buf, len, false);
    }
}

static void ivm_u_cstr(CPUARMState* env, uint64_t va, char* out, size_t max)
{
    size_t i;
    ivm_u_read(env, va, out, max - 1);
    out[max - 1] = 0;
    for (i = 0; out[i]; i++) {
        if (out[i] == '\n' || out[i] == '\r') {
            out[i] = ' ';
        }
    }
}


/* constant CFString {isa, info(0x7c8/0x7d0), char* ptr, len}: return 1 + text, or 2 + unslid ptr if unreadable */
static int ivm_u_cfstr(CPUARMState* env, uint64_t obj, char* out, size_t max, uint64_t* uptr)
{
    uint64_t w[4];
    ivm_u_read(env, obj, w, sizeof(w));
    if (!w[0] || ((w[1] & 0xff) != 0xc8 && (w[1] & 0xff) != 0xd0) || w[3] > 4096 || !w[2]) {
        return 0;
    }
    ivm_u_cstr(env, w[2], out, max);
    if (out[0]) {
        return 1;
    }
    *uptr = w[2] - ivm_dsc_slide;
    return 2;
}

void HELPER(ivm_slide)(CPUARMState* env, uint64_t pc)
{
    uint64_t s = env->xregs[0];
    if (!ivm_dsc_slide && s && !(s & 0x3fff) && s < 0x100000000ull) {
        ivm_dsc_slide = s;
        fprintf(stderr, "[utrace] dsc slide = 0x%" PRIx64 "\n", s);
    }
}

void HELPER(ivm_utrace)(CPUARMState* env, uint64_t pc)
{
    static long hits, max = -1;
    if (max < 0) {
        const char* e = getenv("IVM_KTRACE_N");
        max = e ? atol(e) : 4000;
    }
    if (hits++ >= max) {
        return;
    }
    fprintf(stderr, "[utrace] %" PRIx64 " x0=%" PRIx64 " x1=%" PRIx64 " x2=%" PRIx64 " x3=%" PRIx64 " x4=%" PRIx64
            " x5=%" PRIx64 " x6=%" PRIx64 " x7=%" PRIx64 " lr=%" PRIx64 " sp=%" PRIx64 "\n", pc - ivm_dsc_slide,
            env->xregs[0], env->xregs[1], env->xregs[2], env->xregs[3], env->xregs[4], env->xregs[5],
            env->xregs[6], env->xregs[7], env->xregs[30] - ivm_dsc_slide, env->xregs[31]);
    {   /* decode constant-CFString arguments (property keys) */
        int  r;
        char t[160];
        for (r = 0; r < 4; r++) {
            uint64_t up = 0;
            int      k = ivm_u_cfstr(env, env->xregs[r], t, sizeof(t), &up);
            if (k == 1) {
                fprintf(stderr, "[utrace]   x%d=\"%s\"\n", r, t);
            } else if (k == 2) {
                fprintf(stderr, "[utrace]   x%d=cfs@%" PRIx64 "\n", r, up);
            }
        }
    }
}

/* _os_log_impl(void *dso, os_log_t log, os_log_type_t type, const char *format, uint8_t *buf, uint32_t size)
 * buf: u8 summary, u8 count, then items { u8 desc (type << 4 | flags), u8 size, data[size] }. */
static void ivm_oslog_core(CPUARMState* env, uint64_t dso_va, unsigned type, uint64_t fmt_va, uint64_t buf_va,
                           uint32_t size);
void HELPER(ivm_oslog)(CPUARMState* env, uint64_t pc)
{
    ivm_oslog_core(env, env->xregs[0], (unsigned)(env->xregs[2] & 0xff), env->xregs[3], env->xregs[4],
                   (uint32_t)env->xregs[5]);
}

/* fig_log_emit(?, log, type, os_log_pack_t pack, size_t packsize, ...): pack = {u64 ctime; timespec wall;
 * mh @0x18; pc @0x20; fmt @0x28; data @0x30}. Emitted regardless of gFigLogControl. */
void HELPER(ivm_figlog)(CPUARMState* env, uint64_t pc)
{
    uint64_t p = env->xregs[3], h[6];
    if (!p || env->xregs[4] < 0x32) {
        return;
    }
    ivm_u_read(env, p, h, sizeof(h));
    ivm_oslog_core(env, h[3], 0x80 | (unsigned)(env->xregs[2] & 0x7f), h[5], p + 0x30,
                   (uint32_t)(env->xregs[4] - 0x30));
}

static void ivm_oslog_core(CPUARMState* env, uint64_t dso_va, unsigned type, uint64_t fmt_va, uint64_t buf_va,
                           uint32_t size)
{
    char     fmt[512], out[1536], s[256];
    uint8_t  buf[512];
    uint64_t dso  = dso_va - ivm_dsc_slide;
    size_t   o = 0, bi = 2;
    int      nargs, ai = 0, i;
    const char* f;

    if (ivm_oslog_max < 0) {
        const char* e = getenv("IVM_OSLOG_N");
        ivm_oslog_max = e ? atol(e) : 40000;
        e = getenv("IVM_OSLOG_DSO");
        while (e && *e && ivm_oslog_ndso < 16) {
            char* end;
            ivm_oslog_dso[ivm_oslog_ndso++] = strtoull(e, &end, 16);
            e = (*end == ',') ? end + 1 : NULL;
        }
    }
    if (ivm_oslog_ndso) {
        for (i = 0; i < ivm_oslog_ndso && ivm_oslog_dso[i] != dso; i++) {
        }
        if (i == ivm_oslog_ndso) {
            return;
        }
    }
    if (ivm_oslog_hits++ >= ivm_oslog_max) {
        return;
    }
    if (size > sizeof(buf)) {
        size = sizeof(buf);
    }
    ivm_u_cstr(env, fmt_va, fmt, sizeof(fmt));
    ivm_u_read(env, buf_va, buf, size);
    nargs = size >= 2 ? buf[1] : 0;
    if (!fmt[0]) {   /* format page not faulted in this task: emit unslid ptr + raw items, resolved offline */
        o = snprintf(out, sizeof(out), "@F%" PRIx64 " |", fmt_va - ivm_dsc_slide);
        for (ai = 0; ai < nargs && bi + 2 <= size && o < sizeof(out) - 200; ai++) {
            uint8_t  desc = buf[bi], isz = buf[bi + 1];
            uint64_t v = 0;
            if (bi + 2 + isz > size) {
                break;
            }
            memcpy(&v, buf + bi + 2, isz > 8 ? 8 : isz);
            bi += 2 + isz;
            if ((desc >> 4) == 2) {
                ivm_u_cstr(env, v, s, sizeof(s));
                if (s[0]) {
                    for (i = 0; s[i]; i++) {
                        if (s[i] == ' ' || s[i] == '|') {
                            s[i] = '_';
                        }
                    }
                    o += snprintf(out + o, sizeof(out) - o, " s:%s", s);
                } else {
                    o += snprintf(out + o, sizeof(out) - o, " S:%" PRIx64, v - ivm_dsc_slide);
                }
            } else if ((desc >> 4) == 4) {
                uint64_t up = 0;
                int      r = ivm_u_cfstr(env, v, s, sizeof(s), &up);
                if (r == 1) {
                    for (i = 0; s[i]; i++) {
                        if (s[i] == ' ' || s[i] == '|') {
                            s[i] = '_';
                        }
                    }
                    o += snprintf(out + o, sizeof(out) - o, " s:%s", s);
                } else if (r == 2) {
                    o += snprintf(out + o, sizeof(out) - o, " S:%" PRIx64, up);
                } else {
                    o += snprintf(out + o, sizeof(out) - o, " 4:8:%" PRIx64, v);
                }
            } else {
                o += snprintf(out + o, sizeof(out) - o, " %x:%u:%" PRIx64, desc >> 4, isz, v);
            }
        }
        fprintf(stderr, "[oslog] dso=%" PRIx64 " t=%u %s\n", dso, type, out);
        return;
    }

    for (f = fmt; *f && o < sizeof(out) - 300; f++) {
        const char* spec;
        char        conv;
        uint8_t     desc, isz;
        uint64_t    v = 0;
        if (*f != '%') {
            out[o++] = *f;
            continue;
        }
        if (f[1] == '%') {
            out[o++] = '%';
            f++;
            continue;
        }
        spec = f + 1;
        while (*spec == '{') {             /* %{public}s, %{private,mask.hash}@ ... */
            while (*spec && *spec != '}') {
                spec++;
            }
            if (*spec) {
                spec++;
            }
        }
        while (*spec && !strchr("diouxXscpPfFeEgGaA@SC", *spec)) {
            spec++;
        }
        conv = *spec;
        f = *spec ? spec : spec - 1;
    next_arg:
        if (ai >= nargs || bi + 2 > size) {
            o += snprintf(out + o, sizeof(out) - o, "<?>");
            continue;
        }
        desc = buf[bi];
        isz  = buf[bi + 1];
        if (bi + 2 + isz > size) {
            o += snprintf(out + o, sizeof(out) - o, "<trunc>");
            ai = nargs;
            continue;
        }
        memcpy(&v, buf + bi + 2, isz > 8 ? 8 : isz);
        bi += 2 + isz;
        ai++;
        if ((desc >> 4) == 1) {            /* count/precision item for '*' */
            goto next_arg;
        }
        switch (desc >> 4) {
        case 2:                            /* C string */
            ivm_u_cstr(env, v, s, sizeof(s));
            o += snprintf(out + o, sizeof(out) - o, "%s", s);
            break;
        case 4: {                          /* ObjC/CF object */
            uint64_t up = 0;
            int      r = ivm_u_cfstr(env, v, s, sizeof(s), &up);
            if (r == 1) {
                o += snprintf(out + o, sizeof(out) - o, "%s", s);
            } else if (r == 2) {
                o += snprintf(out + o, sizeof(out) - o, "<cfs@%" PRIx64 ">", up);
            } else {
                o += snprintf(out + o, sizeof(out) - o, "<obj %" PRIx64 ">", v);
            }
            break;
        }
        default:
            if (isz == 4 && v & 0x80000000u && (conv == 'd' || conv == 'i')) {
                v |= 0xffffffff00000000ull;
            }
            if (conv == 'x' || conv == 'X' || conv == 'p' || conv == 'P') {
                o += snprintf(out + o, sizeof(out) - o, "%" PRIx64, v);
            } else if (conv == 'd' || conv == 'i') {
                o += snprintf(out + o, sizeof(out) - o, "%" PRId64, (int64_t)v);
            } else if (conv == 'f' || conv == 'g' || conv == 'e') {
                double d;
                memcpy(&d, &v, 8);
                o += snprintf(out + o, sizeof(out) - o, "%g", d);
            } else {
                o += snprintf(out + o, sizeof(out) - o, "%" PRIu64, v);
            }
            break;
        }
    }
    out[o < sizeof(out) ? o : sizeof(out) - 1] = 0;
    fprintf(stderr, "[oslog] dso=%" PRIx64 " t=%u %s\n", dso, type, out);
}
