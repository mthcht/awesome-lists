rule PUA_Linux_CoinMiner_286382_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Linux/CoinMiner!xmrig"
        threat_id = "286382"
        type = "PUA"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "xmrig: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/xmrig/xmrig/releases/download" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PUA_Linux_CoinMiner_286383_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Linux/CoinMiner!crng"
        threat_id = "286383"
        type = "PUA"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "crng: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cryptonight -o stratum+tcp://pool." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PUA_Linux_CoinMiner_K_305478_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Linux/CoinMiner.K"
        threat_id = "305478"
        type = "PUA"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "proc/cpuinfo" ascii //weight: 1
        $x_1_2 = "max-cpu-usage" ascii //weight: 1
        $x_2_3 = "stratum+tcp://" ascii //weight: 2
        $x_2_4 = "nicehash.com" ascii //weight: 2
        $x_2_5 = {6d 69 6e 65 78 6d 72 2e [0-3] 3a}  //weight: 2, accuracy: Low
        $x_2_6 = "Try `minerd --help" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

