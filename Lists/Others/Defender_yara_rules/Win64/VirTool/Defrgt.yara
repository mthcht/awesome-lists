rule VirTool_Win64_Defrgt_A_2147956701_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Defrgt.A"
        threat_id = "2147956701"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Defrgt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 ff 48 89 7c 24 20 4d 8b cf 49 8b d6 48 8b ce ff}  //weight: 1, accuracy: High
        $x_1_2 = {41 b9 00 80 00 00 45 33 c0 49 8b d6 48 8b ce ff}  //weight: 1, accuracy: High
        $x_1_3 = {49 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

