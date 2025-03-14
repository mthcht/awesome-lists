rule HackTool_MacOS_SuspPortBlock_B_2147936070_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspPortBlock.B"
        threat_id = "2147936070"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspPortBlock"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {62 00 6c 00 6f 00 63 00 6b 00 20 00 64 00 72 00 6f 00 70 00 20 00 [0-16] 70 00 72 00 6f 00 74 00 6f 00 20 00 74 00 63 00 70 00 20 00 66 00 72 00 6f 00 6d 00 20 00 61 00 6e 00 79 00 20 00 74 00 6f 00 20 00 61 00 6e 00 79 00}  //weight: 8, accuracy: Low
        $x_8_2 = {62 00 6c 00 6f 00 63 00 6b 00 20 00 64 00 72 00 6f 00 70 00 20 00 [0-16] 70 00 72 00 6f 00 74 00 6f 00 20 00 75 00 64 00 70 00 20 00 66 00 72 00 6f 00 6d 00 20 00 61 00 6e 00 79 00 20 00 74 00 6f 00 20 00 61 00 6e 00 79 00}  //weight: 8, accuracy: Low
        $x_1_3 = {70 00 6f 00 72 00 74 00 [0-16] 20 00 38 00 30 00}  //weight: 1, accuracy: Low
        $x_1_4 = {70 00 6f 00 72 00 74 00 [0-16] 20 00 34 00 34 00 33 00}  //weight: 1, accuracy: Low
        $x_16_5 = "/etc/pf.conf" wide //weight: 16
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_16_*) and 1 of ($x_8_*) and 1 of ($x_1_*))) or
            ((1 of ($x_16_*) and 2 of ($x_8_*))) or
            (all of ($x*))
        )
}

