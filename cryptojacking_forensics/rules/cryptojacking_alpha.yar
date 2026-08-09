// Cryptojacking rule pack — alpha version 1.0.0
//
// SCOPE: offline byte scanning of supplied artifacts (files, dumps, configs).
// These rules are INDICATORS FOR TRIAGE, not proof of compromise. They are tested
// only against inert synthetic fixtures. They do NOT imply real-world detection
// performance. See docs/VALIDATION.md.
//
// Each rule carries stable metadata so findings can cite provenance:
//   rule_id        stable identifier (used in findings + schemas)
//   version        rule-pack version the rule belongs to
//   author         maintainer
//   purpose        what the rule looks for
//   input_type     "artifact" (byte scan) — "memory" only via a real framework
//   mitre          ATT&CK technique reference where justified (T1496.001)
//   confidence     evidence-strength rationale (strong|medium|weak)
//   false_positives known benign conditions that may trigger
//   reviewed       last-reviewed date
//
// Design choices (see docs/adr/0001):
// - Generic single-token matches (bare ports, "mining", "minerd", loose "xmrig")
//   are avoided or contextualized. Where a generic token is used, we require
//   corroboration with a second distinct indicator in the same scan so a lone
//   occurrence in unrelated documentation is not over-weighted.
// - Severity is NOT set to HIGH merely because a miner name appears in arbitrary
//   bytes. The findings layer reports evidence strength + analytic confidence.

rule cj_miner_xmrig_config_1 {
    meta:
        rule_id = "CJ-MINER-001"
        version = "1.0.0"
        author = "Dimple Nemade"
        purpose = "XMRig configuration/options that co-occur with mining setup"
        input_type = "artifact"
        mitre = "T1496.001"
        confidence = "medium"
        false_positives = "security blog posts, training material, benign config snippets mentioning donate-level/algo/randomx together"
        reviewed = "2026-08-09"
    strings:
        $donate = "donate-level" ascii
        $algo = "randomx" ascii
        $pool_kw = "pool" ascii
        $daemon = "\"daemon\"" ascii
        $rig = "rig-id" ascii
    condition:
        ($donate and ($algo or $pool_kw)) or ($algo and ($daemon or $rig))
}

rule cj_stratum_endpoint_1 {
    meta:
        rule_id = "CJ-NET-001"
        version = "1.0.0"
        author = "Dimple Nemade"
        purpose = "Stratum mining-protocol endpoint URI or common mining ports"
        input_type = "artifact"
        mitre = "T1496.001"
        confidence = "medium"
        false_positives = "non-mining services using ports 3333/4444/5555; documentation describing stratum"
        reviewed = "2026-08-09"
    strings:
        $stcp = "stratum+tcp://" ascii
        $sssl = "stratum+ssl://" ascii
        $sstr = "stratum://" ascii
        $port_3333 = ":3333" ascii
        $port_4444 = ":4444" ascii
        $port_5555 = ":5555" ascii
        $kw_stratum = "stratum" ascii
        $kw_mining = "mining" ascii
        $kw_pool = "pool" ascii
    condition:
        ($stcp or $sssl or $sstr) or
        (($port_3333 or $port_4444 or $port_5555) and ($kw_stratum or $kw_mining or $kw_pool))
}

rule cj_miner_name_weak_1 {
    meta:
        rule_id = "CJ-PROC-001"
        version = "1.0.0"
        author = "Dimple Nemade"
        purpose = "Known miner process/binary names (weak indicator on its own)"
        input_type = "artifact"
        mitre = "T1496.001"
        confidence = "weak"
        false_positives = "mention of miner names in documentation, logs, or code comments"
        reviewed = "2026-08-09"
    strings:
        $xmrig = "xmrig" ascii
        $minerd = "minerd" ascii
        $cn = "cryptonight" ascii
        $sysminerd = "systemd-minerd" ascii
    condition:
        // Weak: name alone is not sufficient. The findings layer marks this as
        // corroboration-only and never as a standalone HIGH-severity verdict.
        1 of ($xmrig, $minerd, $cn, $sysminerd)
}
