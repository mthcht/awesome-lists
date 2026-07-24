rule HackTool_Linux_SuspRivalMinerKill_A_2147974495_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspRivalMinerKill.A"
        threat_id = "2147974495"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspRivalMinerKill"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 73 00 20 00 [0-24] 7c 00 20 00 67 00 72 00 65 00 70 00}  //weight: 10, accuracy: Low
        $x_10_2 = "devtmpfsi" wide //weight: 10
        $x_5_3 = {7c 00 20 00 78 00 61 00 72 00 67 00 73 00 20 00 [0-8] 6b 00 69 00 6c 00 6c 00}  //weight: 5, accuracy: Low
        $x_5_4 = {7c 00 78 00 61 00 72 00 67 00 73 00 20 00 [0-8] 6b 00 69 00 6c 00 6c 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

