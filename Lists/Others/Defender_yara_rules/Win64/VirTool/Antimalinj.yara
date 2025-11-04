rule VirTool_Win64_Antimalinj_A_2147956703_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Antimalinj.A"
        threat_id = "2147956703"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Antimalinj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 49 8b cf 41 b8 00 08 00 00 ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 44 24 38 4c 89 74 24 30 c7 44 24 28 06 00 02 00 44 89 74 24 20 45 33 c9 45 33 c0 48 c7 c1 00 00 00 80 ff}  //weight: 1, accuracy: High
        $x_1_3 = {4c 8b 44 24 58 48 8b 54 24 50 4c 2b c2 b9 01 00 01 00 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

