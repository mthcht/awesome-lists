rule HackTool_Linux_CryptoMiner_A_2147773016_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CryptoMiner.A"
        threat_id = "2147773016"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CryptoMiner"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "xmrig " wide //weight: 10
        $x_1_2 = {73 00 74 00 72 00 61 00 74 00 75 00 6d 00 [0-2] 2b 00 74 00 63 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {73 00 74 00 72 00 61 00 74 00 75 00 6d 00 [0-2] 2b 00 73 00 73 00 6c 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = "--donate-level" wide //weight: 1
        $x_1_5 = "--max-cpu-usage" wide //weight: 1
        $x_1_6 = "--nicehash" wide //weight: 1
        $x_1_7 = "--donate-over-proxy" wide //weight: 1
        $x_1_8 = "--cpu-affinity" wide //weight: 1
        $x_1_9 = "--cpu-max-threads-hint" wide //weight: 1
        $x_1_10 = "--cpu-priority" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

