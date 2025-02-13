rule HackTool_Linux_SuspPrivilegedBit_A_2147789195_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspPrivilegedBit.A"
        threat_id = "2147789195"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspPrivilegedBit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "chmod " wide //weight: 5
        $x_1_2 = "u+s " wide //weight: 1
        $x_1_3 = "g+s " wide //weight: 1
        $x_1_4 = "+s " wide //weight: 1
        $x_1_5 = "+t " wide //weight: 1
        $x_6_6 = {63 00 68 00 6d 00 6f 00 64 00 20 00 23 01 01 01 30 22 01 01 03 31 32 34 22 03 03 03 30 2d 37 20 00}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

