rule HackTool_Linux_SuspGdbPrivEsc_A_2147957989_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspGdbPrivEsc.A"
        threat_id = "2147957989"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspGdbPrivEsc"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2d 00 65 00 78 00 [0-6] 70 00 79 00 74 00 68 00 6f 00 6e 00}  //weight: 10, accuracy: Low
        $x_15_2 = {6f 00 73 00 2e 00 73 00 65 00 74 00 75 00 69 00 64 00 [0-4] 28 00 [0-4] 30 00}  //weight: 15, accuracy: Low
        $x_2_3 = {2d 00 65 00 78 00 [0-6] 21 00 64 00 61 00 73 00 68 00}  //weight: 2, accuracy: Low
        $x_2_4 = {2d 00 65 00 78 00 [0-6] 21 00 73 00 68 00}  //weight: 2, accuracy: Low
        $x_2_5 = {2d 00 65 00 78 00 [0-6] 21 00 62 00 61 00 73 00 68 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

