#!/usr/bin/env python3
"""s33 EXPERIMENT: give iOS performance (P / Lightning) cores.

The t8030 device tree lists cpu0-3 = E (Thunder, cluster 0) then cpu4-5 = P (Lightning, cluster 1).
t8030_cpu_setup keeps the FIRST N nodes, so with 4 iOS cores the guest sees four E cores and no P cluster.
iOS's AMP scheduler / CLPC place UI threads on P cores; on an E-only topology everything shares one
"efficiency" pset. With IVM_PCORES=k (1..2) we keep N-k E nodes + k P nodes instead (in DT order, E first)
and renumber "cpu-id" 0..N-1 so vCPU index == cpu-id still holds (AIC / PMGR cpu-start mask / IPI tables
are indexed by it). reg (phys id 0x10x for cluster 1) and cluster-id stay real, so MPIDR/IPI routing match.
Default (unset / 0) = upstream behaviour. Logs the chosen topology as "IVM-PCORES ...".
"""
import sys, pathlib
p = pathlib.Path(sys.argv[1]) / "hw/arm/t8030.c"
s = p.read_text()

old = """    for (iter = root->children, i = 0; iter; iter = next, ++i) {
        uint32_t     cluster_id;
        AppleDTNode* node;

        next = iter->next;
        node = (AppleDTNode*)iter->data;
        if (i >= t8030_real_cpu_count(t8030)) {
            apple_dt_del_node(root, node);
            continue;
        }

        t8030->cpus[i] = apple_a13_from_node(node);"""
new = """    /* ivm pcores: choose which DT cpu nodes survive (see exp/pcores.py) */
    {
        const char*  pe     = getenv("IVM_PCORES");
        unsigned int want_p = pe ? (unsigned int)atoi(pe) : 0;
        unsigned int n      = t8030_real_cpu_count(t8030);
        if (want_p > 0) {
            unsigned int n_p = 0, n_e = 0, keep_e, keep_p;
            for (iter = root->children; iter; iter = iter->next) {
                if (apple_dt_get_prop_u16_or((AppleDTNode*)iter->data, "cluster-type", 0, NULL) == 'P') { n_p++; }
                else { n_e++; }
            }
            keep_p = MIN(want_p, n_p);
            if (keep_p > n - 1) { keep_p = n - 1; }   /* the boot cpu (cpu0) is an E core */
            keep_e = n - keep_p;
            if (keep_e > n_e) { keep_e = n_e; keep_p = MIN(n_p, n - keep_e); }
            unsigned int se = 0, sp = 0, id = 0;
            for (iter = root->children; iter; iter = next) {
                AppleDTNode* node = (AppleDTNode*)iter->data;
                bool         isp  = apple_dt_get_prop_u16_or(node, "cluster-type", 0, NULL) == 'P';
                next              = iter->next;
                if ((isp && sp >= keep_p) || (!isp && se >= keep_e)) {
                    apple_dt_del_node(root, node);
                    continue;
                }
                if (isp) { sp++; } else { se++; }
                apple_dt_set_prop_u32(node, "cpu-id", id);
                fprintf(stderr, "IVM-PCORES cpu-id %u type %c cluster %u reg 0x%x\\n", id, isp ? 'P' : 'E',
                        apple_dt_get_prop_u32(node, "cluster-id", &error_fatal),
                        apple_dt_get_prop_u32(node, "reg", &error_fatal));
                id++;
            }
        }
    }

    for (iter = root->children, i = 0; iter; iter = next, ++i) {
        uint32_t     cluster_id;
        AppleDTNode* node;

        next = iter->next;
        node = (AppleDTNode*)iter->data;
        if (i >= t8030_real_cpu_count(t8030)) {
            apple_dt_del_node(root, node);
            continue;
        }

        t8030->cpus[i] = apple_a13_from_node(node);"""
if s.count(old) != 1: sys.exit(f"pcores: anchor x{s.count(old)}")
s = s.replace(old, new)
p.write_text(s)
print("pcores: applied")
