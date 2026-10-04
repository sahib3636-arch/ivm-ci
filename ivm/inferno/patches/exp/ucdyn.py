#!/usr/bin/env python3
"""s38: frame- and thermal-gated speed hints (apply after android-perf; fpslog optional).

Phone evidence (4.0.33 recording): memory pressure gone (swap 0.16 GB, faults 0-25/s) but the S24U went
thermal "moderate" (headroom 88 -> 92 %) ~2.5 min after boot and dropped mid/prime clocks from 2380 to
~1500-1700 MHz. The engine burned 3-4 host cores even at 0-2 fps (iOS post-boot background work; CI shows the
same 2.5-3 cores right after unlock, 0.3 cores once settled), and the 4.0.32 static uclamp_min (90 % of the
cluster capacity) forced near-max clocks for that invisible background work too -> heat -> throttling exactly
when the user then scrolls.

Now a controller thread (50 ms) watches the iOS display commit counter (CONTROL_UPDATE COMMIT = a frame iOS
produced) and, optionally, a thermal file written by the app ("<status> <headroom>", IVM_THERMAL_FILE):
  * frames in the last 1.5 s, cool       -> uclamp_min = IVM_UCLAMP_MIN (unchanged 4.0.32 behaviour)
  * frames in the last 1.5 s, status>=2 or headroom>=0.85 -> uclamp_min = 2/3 of it
  * no frames for 1.5 s (static screen; background work only) -> uclamp_min = 0 (plain schedutil)
and the ADPF reporter stops asking for more speed while no frames are produced. A frame re-arms the floor
within 50 ms. IVM_UCDYN=0 restores the static floor. One stats line per minute ("[ivm-perf] uclamp ...").
"""
import sys, pathlib
root = pathlib.Path(sys.argv[1])
def sub(rel, old, new, cnt=1):
    p = root / rel; s = p.read_text()
    if s.count(old) != cnt: sys.exit(f"ucdyn: {rel}: anchor x{s.count(old)}: {old[:60]!r}")
    p.write_text(s.replace(old, new))

D = "hw/display/apple_displaypipe_v4.c"
sub(D, "REG32(CONTROL_VERSION, 0x46020)\n", "uint64_t ivm_frame_seq;   /* ivm ucdyn: frames committed by iOS */\nREG32(CONTROL_VERSION, 0x46020)\n")
sub(D, "            if (REG_FIELD_EX32((uint32_t)data, CONTROL_UPDATE, COMMIT)) {\n",
       "            if (REG_FIELD_EX32((uint32_t)data, CONTROL_UPDATE, COMMIT)) {\n                qatomic_inc(&ivm_frame_seq);\n")

M = "accel/tcg/tcg-accel-ops-mttcg.c"
# controller + registry, placed before the ADPF reporter so it can read ivm_uc_active
sub(M, "static void* ivm_hint_reporter(void* arg)\n{\n", r'''extern uint64_t ivm_frame_seq;
static int       ivm_uc_tid[IVM_HINT_MAX];
static int       ivm_uc_n;
static unsigned  ivm_uc_floor;
static int       ivm_uc_active = 1;   /* frames recently -> ADPF may ask for speed */
static bool      ivm_uc_started;

static void ivm_uc_set(unsigned v)
{
    struct ivm_sched_attr at = { 0 };
    int i;
    at.size = sizeof(at);
    at.sched_flags = 0x08 | 0x10 | 0x20;   /* KEEP_POLICY | KEEP_PARAMS | UTIL_CLAMP_MIN */
    at.sched_util_min = v;
    pthread_mutex_lock(&ivm_hint_mu);
    for (i = 0; i < ivm_uc_n; i++) { syscall(SYS_sched_setattr, ivm_uc_tid[i], &at, 0); }
    pthread_mutex_unlock(&ivm_hint_mu);
}

static void* ivm_uc_ctl(void* arg)
{
    const char* tf = getenv("IVM_THERMAL_FILE");
    uint64_t seq = qatomic_read(&ivm_frame_seq);
    int64_t last_frame = ivm_now_ns(), last_th = 0, t_min = ivm_now_ns();
    unsigned cur = ivm_uc_floor, want;
    int th_status = -1; double th_head = -1;
    long n_full = 0, n_hot = 0, n_off = 0, n = 0, changes = 0;
    (void)arg;
    for (;;) {
        struct timespec d = { 0, 50000000 };
        int64_t now; uint64_t s; bool hot;
        nanosleep(&d, NULL);
        now = ivm_now_ns();
        s = qatomic_read(&ivm_frame_seq);
        if (s != seq) { seq = s; last_frame = now; }
        if (tf && now - last_th > 1000000000LL) {
            FILE* f = fopen(tf, "r");
            last_th = now;
            if (f) { int st; double h; if (fscanf(f, "%d %lf", &st, &h) == 2) { th_status = st; th_head = h; } fclose(f); }
        }
        hot = th_status >= 2 || th_head >= 0.85;
        if (now - last_frame < 1500000000LL) { want = hot ? ivm_uc_floor * 2 / 3 : ivm_uc_floor; qatomic_set(&ivm_uc_active, 1); }
        else { want = 0; qatomic_set(&ivm_uc_active, 0); }
        if (want != cur) { ivm_uc_set(want); cur = want; changes++; }
        n++; if (want == 0) { n_off++; } else if (want < ivm_uc_floor) { n_hot++; } else { n_full++; }
        if (now - t_min >= 60000000000LL) {
            fprintf(stderr, "[ivm-perf] uclamp last minute: floor %u %ld%%, reduced (hot) %ld%%, off (no frames) %ld%%, %ld changes, thermal %d/%.2f\n",
                    ivm_uc_floor, n_full * 100 / n, n_hot * 100 / n, n_off * 100 / n, changes, th_status, th_head);
            n = n_full = n_hot = n_off = changes = 0; t_min = now;
        }
    }
    return NULL;
}

static void* ivm_hint_reporter(void* arg)
{
''')
# ADPF: no "more speed" requests while iOS shows no frames
sub(M, "        if (act < 1000000) act = 1000000;\n",
       "        if (act < 1000000) act = 1000000;\n        if (!qatomic_read(&ivm_uc_active) && act > target * 9 / 10) act = target * 9 / 10;\n")
# register uclamp threads + start the controller
sub(M, "        else\n            fprintf(stderr, \"[ivm-perf] uclamp_min %u on tid %d\\n\", at.sched_util_min, tid);\n    }\n",
       "        else {\n            const char* dyn = getenv(\"IVM_UCDYN\");\n"
       "            fprintf(stderr, \"[ivm-perf] uclamp_min %u on tid %d%s\\n\", at.sched_util_min, tid,\n"
       "                    dyn && !strcmp(dyn, \"0\") ? \"\" : \" (frame/thermal gated)\");\n"
       "            if (!(dyn && !strcmp(dyn, \"0\"))) {\n"
       "                pthread_mutex_lock(&ivm_hint_mu);\n"
       "                if (ivm_uc_n < IVM_HINT_MAX) { ivm_uc_tid[ivm_uc_n++] = tid; }\n"
       "                ivm_uc_floor = at.sched_util_min;\n"
       "                if (!ivm_uc_started) {\n"
       "                    pthread_t r;\n"
       "                    ivm_uc_started = true;\n"
       "                    if (pthread_create(&r, NULL, ivm_uc_ctl, NULL) == 0) { pthread_detach(r); }\n"
       "                }\n"
       "                pthread_mutex_unlock(&ivm_hint_mu);\n"
       "            }\n        }\n    }\n")
print("ucdyn: ok")
