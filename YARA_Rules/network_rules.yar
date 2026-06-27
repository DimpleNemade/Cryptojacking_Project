rule crypto_network_indicators {
meta:
author = "Dimple"
description = "Detects crypto-mining network patterns"
strings:
$s1 = "stratum" nocase
$s2 = ":3333"
$s3 = ":4444"
$s4 = "/json_rpc"
condition:
any of ($s1, $s2, $s3, $s4)
}
