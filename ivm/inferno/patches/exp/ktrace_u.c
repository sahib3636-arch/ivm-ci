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
    static long     hits, max = -1;
    static int64_t  lr_lo = -1;
    static uint64_t lr_hi;
    if (max < 0) {
        const char* e = getenv("IVM_KTRACE_N");
        max = e ? atol(e) : 4000;
    }
    if (lr_lo < 0) {   /* IVM_UTRACE_LR=lo-hi (unslid): only report calls whose caller (lr) is in range */
        const char* e = getenv("IVM_UTRACE_LR");
        char*       end;
        lr_lo = 0;
        if (e) {
            lr_lo = (int64_t)strtoull(e, &end, 16);
            lr_hi = (*end == '-') ? strtoull(end + 1, NULL, 16) : 0;
        }
    }
    if (lr_hi && (env->xregs[30] - ivm_dsc_slide < (uint64_t)lr_lo || env->xregs[30] - ivm_dsc_slide >= lr_hi)) {
        return;
    }
    if (hits++ >= max) {
        return;
    }
    {   /* 8 bytes at x1/x2 (CFNumberCreate valuePtr etc.) */
        uint64_t m1 = 0, m2 = 0;
        ivm_u_read(env, env->xregs[1], &m1, 8);
        ivm_u_read(env, env->xregs[2], &m2, 8);
        fprintf(stderr, "[utrace]   [x1]=%" PRIx64 " [x2]=%" PRIx64 "\n", m1, m2);
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
    if (getenv("IVM_UTRACE_BT")) {   /* s40: unslid user frame-pointer backtrace + NSException name/reason (x0) */
        uint64_t fp = env->xregs[29], fr[2], ex[3] = { 0, 0, 0 };
        int      d;
        char     t[200];
        for (d = 0; d < 20 && fp && !(fp & 7); d++) {
            fr[0] = fr[1] = 0;
            ivm_u_read(env, fp, fr, sizeof(fr));
            if (!fr[1]) {
                break;
            }
            fprintf(stderr, "[utrace]   bt#%d %" PRIx64 "\n", d, (fr[1] & 0xfffffffffULL) - ivm_dsc_slide);
            fp = fr[0];
        }
        ivm_u_read(env, env->xregs[0], ex, sizeof(ex));
        for (d = 1; d < 3; d++) {
            uint64_t up = 0;
            if (ivm_u_cfstr(env, ex[d], t, sizeof(t), &up) == 1) {
                fprintf(stderr, "[utrace]   exc[%d]=\"%s\"\n", d, t);
            } else {   /* dynamic NSString: show the printable bytes of the object and of its first pointer */
                uint8_t raw[160];
                uint64_t p2[3] = { 0, 0, 0 };
                int      i, o = 0;
                ivm_u_read(env, ex[d], raw, sizeof(raw));
                memcpy(p2, raw, sizeof(p2));
                for (i = 16; i < (int)sizeof(raw) && o < (int)sizeof(t) - 1; i++) {
                    t[o++] = (raw[i] >= 32 && raw[i] < 127) ? raw[i] : '.';
                }
                t[o] = 0;
                fprintf(stderr, "[utrace]   exc[%d]=%" PRIx64 " raw:%s\n", d, ex[d], t);
                ivm_u_read(env, p2[2], raw, sizeof(raw));
                for (i = o = 0; i < (int)sizeof(raw) && o < (int)sizeof(t) - 1; i++) {
                    t[o++] = (raw[i] >= 32 && raw[i] < 127) ? raw[i] : '.';
                }
                t[o] = 0;
                fprintf(stderr, "[utrace]   exc[%d] *p2:%s\n", d, t);
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
 * mh @0x18; pc @0x20; fmt @0x28; errno u16 @0x40; size u16 @0x42; data @0x44} (libtrace _os_log_pack_fill). Emitted regardless of gFigLogControl. */
void HELPER(ivm_figlog)(CPUARMState* env, uint64_t pc)
{
    uint64_t p = env->xregs[3], h[6];
    if (!p || env->xregs[4] < 0x46) {
        return;
    }
    ivm_u_read(env, p, h, sizeof(h));
    ivm_oslog_core(env, h[3], 0x80 | (unsigned)(env->xregs[2] & 0x7f), h[5], p + 0x44,
                   (uint32_t)(env->xregs[4] - 0x44));
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

/* Kernel os_log mirror: IVM_KOSLOG=<VA of _os_log_internal> (kernel, no slide with kaslr off).
 * _os_log_internal(dso, log, type, fmt, ...) - Darwin variadics live on the stack, one 8-byte slot each. */
void HELPER(ivm_koslog)(CPUARMState* env, uint64_t pc)
{
    static long n, max = -1;
    char        fmt[400], out[1200], s[200];
    uint64_t    st[16];
    size_t      o = 0;
    int         ai = 0, i;
    const char* f;
    if (max < 0) {
        const char* e = getenv("IVM_KOSLOG_N");
        max = e ? atol(e) : 50000;
    }
    if (n++ >= max) {
        return;
    }
    ivm_u_cstr(env, env->xregs[3], fmt, sizeof(fmt));
    ivm_u_read(env, env->xregs[31], st, sizeof(st));
    for (f = fmt; *f && o < sizeof(out) - 260; f++) {
        const char* spec;
        char        conv;
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
        while (*spec == '{') {
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
        f    = *spec ? spec : spec - 1;
        if (ai >= 16) {
            o += snprintf(out + o, sizeof(out) - o, "<?>");
            continue;
        }
        if (conv == 's') {
            ivm_u_cstr(env, st[ai++], s, sizeof(s));
            o += snprintf(out + o, sizeof(out) - o, "%s", s);
        } else if (conv == 'x' || conv == 'X' || conv == 'p' || conv == 'P') {
            o += snprintf(out + o, sizeof(out) - o, "%" PRIx64, st[ai++]);
        } else if (conv == 'd' || conv == 'i') {
            o += snprintf(out + o, sizeof(out) - o, "%d", (int)st[ai++]);
        } else {
            o += snprintf(out + o, sizeof(out) - o, "%" PRIu64, st[ai++]);
        }
    }
    out[o] = 0;
    for (i = 0; out[i]; i++) {
        if (out[i] == '\n') {
            out[i] = ' ';
        }
    }
    {   /* IVM_KOSLOG_GREP=substring: only matching lines count/print */
        static const char* g = (const char*)1;
        if (g == (const char*)1) {
            g = getenv("IVM_KOSLOG_GREP");
        }
        if (g && !strstr(out, g)) {
            n--;
            return;
        }
    }
    fprintf(stderr, "[koslog] %s\n", out);
}

/* ---- IVM_LOCKFIX=<unslid pc>,<xreg>,<signed hex off>: at pc, if w0 != 0 (error path), release the
 * os_unfair_lock at [x<reg> + off] by storing 0.  Works around Apple's lock leak in
 * FigPhotoCompressionSessionCopyJPEGEncodeSession when FigPhotoJPEGEncodeSessionCreate fails (no HW JPEG):
 * the next call re-locks on the same thread -> __os_unfair_lock_recursive_abort -> mediaserverd SIGTRAP. */
uint64_t ivm_lockfix_pc;
static int     ivm_lockfix_reg;
static int64_t ivm_lockfix_off;
static long    ivm_lockfix_hits;
static void __attribute__((constructor)) ivm_lockfix_init(void)
{
    const char* e = getenv("IVM_LOCKFIX");
    char*       end;
    if (!e) {
        return;
    }
    ivm_lockfix_pc = strtoull(e, &end, 16);
    if (*end == ',') {
        ivm_lockfix_reg = (int)strtol(end + 1, &end, 10);
    }
    if (*end == ',') {
        ivm_lockfix_off = strtoll(end + 1, &end, 16);
    }
    if (ivm_lockfix_reg < 0 || ivm_lockfix_reg > 30) {
        ivm_lockfix_pc = 0;
    }
}
void HELPER(ivm_lockfix)(CPUARMState* env, uint64_t pc)
{
    uint32_t v = 0, z = 0;
    uint64_t a;
    if ((uint32_t)env->xregs[0] == 0) {
        return;
    }
    a = env->xregs[ivm_lockfix_reg] + ivm_lockfix_off;
    cpu_memory_rw_debug(env_cpu(env), a, &v, 4, false);
    if (v) {
        cpu_memory_rw_debug(env_cpu(env), a, &z, 4, true);
    }
    if (ivm_lockfix_hits++ < 50) {
        fprintf(stderr, "[lockfix] pc=%" PRIx64 " err=%d lock@%" PRIx64 " was %x -> 0\n", pc, (int32_t)env->xregs[0], a, v);
    }
}

/* ---- IVM_USKIP=<fn pc>/<OBJC_IVAR offset var>[,...] (unslid dsc addresses): at an ObjC method entry, if
 * self->ivar == nil, return immediately (x0 = 0, pc = lr).  Used for camera graph nodes whose Metal
 * object failed to load (no GPU in the VM), e.g. BWMultiFilterThumbnailNode._filter (FigColorCubeMetalFilter)
 * which -prepareForCurrentConfigurationToBecomeLive dereferences unconditionally -> mediaserverd SIGSEGV. */
int             ivm_uskip_n;
uint64_t        ivm_uskip_pc[8];
static uint64_t ivm_uskip_ivar[8];
static long     ivm_uskip_hits;
static void __attribute__((constructor)) ivm_uskip_init(void)
{
    const char* e = getenv("IVM_USKIP");
    while (e && *e && ivm_uskip_n < 8) {
        char* end;
        ivm_uskip_pc[ivm_uskip_n] = strtoull(e, &end, 16);
        if (*end != '/') {
            break;
        }
        ivm_uskip_ivar[ivm_uskip_n++] = strtoull(end + 1, &end, 16);
        e = (*end == ',') ? end + 1 : NULL;
    }
}
void HELPER(ivm_uskip)(CPUARMState* env, uint64_t pc)
{
    extern uint64_t ivm_dsc_slide;
    int             k;
    int32_t         off = 0;
    uint64_t        v   = 1;
    for (k = 0; k < ivm_uskip_n; k++) {
        if (ivm_uskip_pc[k] + ivm_dsc_slide == pc) {
            break;
        }
    }
    if (k == ivm_uskip_n || !env->xregs[0]) {
        return;
    }
    if (cpu_memory_rw_debug(env_cpu(env), ivm_uskip_ivar[k] + ivm_dsc_slide, &off, 4, false) ||
        cpu_memory_rw_debug(env_cpu(env), env->xregs[0] + off, &v, 8, false) || v) {
        return;
    }
    if (ivm_uskip_hits++ < 20) {
        fprintf(stderr, "[uskip] pc=%" PRIx64 " self=%" PRIx64 " ivar+%x nil -> return to %" PRIx64 "\n", pc, env->xregs[0], off,
                env->xregs[30]);
    }
    env->xregs[0] = 0;
    env->pc       = env->xregs[30];
    cpu_loop_exit(env_cpu(env));
}

/* ---- IVM_USET=<pc>:<reg>=<hex val>[,...] (unslid dsc addresses, max 8): before the instruction at pc
 * executes, set x<reg> = val.  s39: force CMPhoto option reads, e.g. JPEGSoftwareEncode in
 * FigPhotoJPEGEncoder (MediaToolbox 0x18c250eb0: w0 = option value -> 1) since the VM has no AppleJPEG HW. */
int             ivm_uset_n;
uint64_t        ivm_uset_pc[12];
static uint32_t ivm_uset_reg[12];
static uint64_t ivm_uset_val[12];
static int      ivm_uset_cond[12];
static long     ivm_uset_hits;
static void __attribute__((constructor)) ivm_uset_init(void)
{
    const char* e = getenv("IVM_USET");
    while (e && *e && ivm_uset_n < 12) {
        char* end;
        ivm_uset_pc[ivm_uset_n] = strtoull(e, &end, 16);
        if (*end != ':') {
            break;
        }
        ivm_uset_reg[ivm_uset_n] = (uint32_t)strtoul(end + 1, &end, 10) & 31;
        if (*end != '=') {
            break;
        }
        ivm_uset_val[ivm_uset_n] = strtoull(end + 1, &end, 16);
        ivm_uset_cond[ivm_uset_n] = -1;
        if (*end == '/') {   /* s40: "pc:reg=val/zreg" = only when x[zreg] == 0 */
            ivm_uset_cond[ivm_uset_n] = (int)(strtoul(end + 1, &end, 10) & 31);
        }
        ivm_uset_n++;
        e = (*end == ',') ? end + 1 : NULL;
    }
}
void HELPER(ivm_uset)(CPUARMState* env, uint64_t pc)
{
    extern uint64_t ivm_dsc_slide;
    int             k;
    for (k = 0; k < ivm_uset_n; k++) {
        if (ivm_uset_pc[k] + ivm_dsc_slide == pc && ivm_uset_reg[k] < 31 &&
            (ivm_uset_cond[k] < 0 || (ivm_uset_cond[k] < 31 && !env->xregs[ivm_uset_cond[k]]))) {
            static long per[12];
            ivm_uset_hits++;
            if (per[k]++ < 6) {   /* s40: per-entry cap so every entry shows up */
                fprintf(stderr, "[uset] pc=%" PRIx64 " x%u %" PRIx64 " -> %" PRIx64 "\n", pc, ivm_uset_reg[k],
                        env->xregs[ivm_uset_reg[k]], ivm_uset_val[k]);
            }
            env->xregs[ivm_uset_reg[k]] = ivm_uset_val[k];
        }
    }
}
