rule HackTool_AndroidOS_ZergRush_B_2147685125_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/ZergRush.B"
        threat_id = "2147685125"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "ZergRush"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 62 6f 6f 6d 73 68 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 7a 7a 7a 7a 73 68 00}  //weight: 1, accuracy: High
        $x_10_3 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 76 6f 6c 64 00}  //weight: 10, accuracy: High
        $x_10_4 = {41 6e 64 72 6f 69 64 20 32 2e 32 2f 32 2e 33 20 6c 6f 63 61 6c 20 72 6f 6f 74 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

