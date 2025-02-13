rule HackTool_Linux_LinTools_A_2147925733_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/LinTools.A"
        threat_id = "2147925733"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "LinTools"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "git clone" wide //weight: 1
        $x_1_2 = "wget" wide //weight: 1
        $x_1_3 = "curl" wide //weight: 1
        $x_10_4 = {67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 23 ff ff 0e 61 2d 7a 41 2d 5a 30 2d 39 5f 7e 2e 2f 2d 50 00 45 00 41 00 53 00 53 00 2d 00 6e 00 67 00}  //weight: 10, accuracy: Low
        $x_10_5 = {67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 23 ff ff 0e 61 2d 7a 41 2d 5a 30 2d 39 5f 7e 2e 2f 2d 4c 00 69 00 6e 00 45 00 6e 00 75 00 6d 00}  //weight: 10, accuracy: Low
        $x_10_6 = {67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 23 ff ff 0e 61 2d 7a 41 2d 5a 30 2d 39 5f 7e 2e 2f 2d 6c 00 69 00 6e 00 69 00 6b 00 61 00 74 00 7a 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

