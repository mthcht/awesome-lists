rule HackTool_Linux_CoinMiner_BR1_2147967185_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CoinMiner.BR1"
        threat_id = "2147967185"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CoinMiner"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "curl " wide //weight: 1
        $x_1_2 = "wget " wide //weight: 1
        $x_10_3 = {2e 00 67 00 69 00 74 00 68 00 75 00 62 00 [0-255] 78 00 6d 00 72 00 69 00 67 00}  //weight: 10, accuracy: Low
        $x_10_4 = {2e 00 67 00 69 00 74 00 68 00 75 00 62 00 [0-255] 4d 00 6f 00 6e 00 65 00 72 00 6f 00 4f 00 63 00 65 00 61 00 6e 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

