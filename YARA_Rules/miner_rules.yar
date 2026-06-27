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

rule generic_startum_miner {
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

rule wallet_like_strings {
    meta:
        family = "wallet_hint"
        descripttion = "Wallet-style strings (very rough)"
    strings:
        // BTC-style (very approximate)
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/

        //XMR-style (very approximate)
        $xmr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/

    condition:
        any of ($btc,$xmr)
}
