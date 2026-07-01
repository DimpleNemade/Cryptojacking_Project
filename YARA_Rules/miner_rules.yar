rule xmrig_indicators {
   meta:
       family = "xmrig"
       description = "Xmrig cryptominer binary/config indicators"

   strings:
       $name1 = "xmrig"
       $name2 = "XMRig" nocase
       $cfg1 = "donate-level"
       $cfg2 = "algo" ascii
       $cfg3 = "randomx" ascii

   condition:
       1 of ($name*) or 2 of ($cfg*)
}

rule generic_stratum_miner {
    meta:
        family = "generic_stratum"
        description = "Generic stratum-based mining traffic/config"
    strings:
        $s1 = "stratum+tcp" ascii
        $s2 = "stratum+ssl" ascii
        $p1 = ":3333" ascii
        $p2 = ":5555" ascii
        $w1 = ".pool" ascii
        $w2 = "mining" ascii
    condition:
        (1 of ($s*) and (1 of ($p*) or 1 of ($w*)))
}
