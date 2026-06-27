rule miner_process_names {
meta:
author = "Dimple"
description = "Common miner process names in memory"
strings:
$p1 = "xmrig"
$p2 = "minerd"
$p3 = "cryptonight"
$p4 = "systemd-minerd"
condition:
any of ($p1, $p2, $p3, $p4)
}

