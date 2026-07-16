rule HackTool_Linux_SuspShadowExfil_PA_2147973820_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspShadowExfil.PA"
        threat_id = "2147973820"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspShadowExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 61 00 74 00 20 00 [0-4] 2f 00 65 00 74 00 63 00 2f 00 73 00 68 00 61 00 64 00 6f 00 77 00}  //weight: 10, accuracy: Low
        $x_5_2 = {62 00 61 00 73 00 65 00 36 00 34 00 [0-16] 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
        $x_5_3 = {62 00 61 00 73 00 65 00 36 00 34 00 [0-16] 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_SuspShadowExfil_PB_2147973821_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspShadowExfil.PB"
        threat_id = "2147973821"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspShadowExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 61 00 74 00 20 00 [0-4] 2f 00 65 00 74 00 63 00 2f 00 73 00 68 00 61 00 64 00 6f 00 77 00}  //weight: 10, accuracy: Low
        $x_5_2 = {67 00 7a 00 69 00 70 00 [0-16] 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
        $x_5_3 = {67 00 7a 00 69 00 70 00 [0-16] 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_SuspShadowExfil_PC_2147973822_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspShadowExfil.PC"
        threat_id = "2147973822"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspShadowExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 00 61 00 72 00 20 00 [0-16] 2f 00 65 00 74 00 63 00 2f 00 73 00 68 00 61 00 64 00 6f 00 77 00}  //weight: 10, accuracy: Low
        $x_5_2 = {62 00 61 00 73 00 65 00 36 00 34 00 [0-16] 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
        $x_5_3 = {62 00 61 00 73 00 65 00 36 00 34 00 [0-16] 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
        $x_5_4 = {67 00 7a 00 69 00 70 00 [0-16] 7c 00 [0-4] 63 00 75 00 72 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
        $x_5_5 = {67 00 7a 00 69 00 70 00 [0-16] 7c 00 [0-4] 77 00 67 00 65 00 74 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

