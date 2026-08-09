// Cryptojacking rule pack - alpha version 1.0.0
//
// Scope: offline byte scanning of supplied artifacts (files, dumps, configs).
// These rules are indicators for triage, not proof of compromise. They are
// tested only against inert synthetic fixtures and do not imply real-world
// detection performance. See docs/VALIDATION.md.

rule cj_miner_xmrig_config_1 {
    meta:
        rule_id = "CJ-MINER-001"
        version = "1.0.0"
        author = "Dimple Nemade"
        purpose = "XMRig configuration/options that co-occur with mining setup"
        input_type = "artifact"
        mitre = "T1496.001"
        reference = "https://xmrig.com/docs/miner/config"
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
        reference = "https://attack.mitre.org/techniques/T1496/001/"
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
        (($port_3333 or $port_4444 or $port_5555) and
         ($kw_stratum or $kw_mining or $kw_pool))
}

rule cj_miner_name_weak_1 {
    meta:
        rule_id = "CJ-PROC-001"
        version = "1.0.0"
        author = "Dimple Nemade"
        purpose = "Known miner process/binary names (weak indicator on its own)"
        input_type = "artifact"
        mitre = "T1496.001"
        reference = "https://attack.mitre.org/techniques/T1496/001/"
        confidence = "weak"
        false_positives = "mention of miner names in documentation, logs, or code comments"
        reviewed = "2026-08-09"
    strings:
        $xmrig = "xmrig" ascii
        $minerd = "minerd" ascii
        $cn = "cryptonight" ascii
        $sysminerd = "systemd-minerd" ascii
    condition:
        // A name alone is weak evidence and never a high-confidence conclusion.
        1 of ($xmrig, $minerd, $cn, $sysminerd)
}
