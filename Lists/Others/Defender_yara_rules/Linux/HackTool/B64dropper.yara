rule HackTool_Linux_B64dropper_A_2147842706_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/B64dropper.A"
        threat_id = "2147842706"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "B64dropper"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 00 63 00 68 00 6f 00 27 ff ff 00 23 ff ff 0e 61 2d 7a 41 2d 5a 30 2d 39 2b 2f 3d 22 27 27 ff ff 00 7c 00 27 ff ff 00 62 00 61 00 73 00 65 00 36 00 34 00 27 ff ff 00 2d 00 64 00 27 ff ff 00 7c 00 27 ff ff 00 2b 02 02 00 73 00 68 00}  //weight: 1, accuracy: Low
        $x_1_2 = {65 00 63 00 68 00 6f 00 27 ff ff 00 23 ff ff 0e 61 2d 7a 41 2d 5a 30 2d 39 2b 2f 3d 22 27 27 ff ff 00 7c 00 27 ff ff 00 62 00 61 00 73 00 65 00 36 00 34 00 27 ff ff 00 2d 00 2d 00 64 00 65 00 63 00 6f 00 64 00 65 00 27 ff ff 00 7c 00 27 ff ff 00 2b 02 02 00 73 00 68 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

