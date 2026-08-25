rule HackTool_Linux_SuspKworkerMasqStage_A_2147976943_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspKworkerMasqStage.A"
        threat_id = "2147976943"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspKworkerMasqStage"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 75 00 72 00 6c 00 20 00 [0-255] 2d 00 6f 00 20 00 [0-4] 2f 00 64 00 65 00 76 00 2f 00 73 00 68 00 6d 00 2f 00 [0-48] 6b 00 77 00 6f 00 72 00 6b 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 67 00 65 00 74 00 20 00 [0-255] 2d 00 6f 00 20 00 [0-4] 2f 00 64 00 65 00 76 00 2f 00 73 00 68 00 6d 00 2f 00 [0-48] 6b 00 77 00 6f 00 72 00 6b 00 65 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

