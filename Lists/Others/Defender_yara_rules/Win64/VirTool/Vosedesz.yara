rule VirTool_Win64_Vosedesz_A_2147978709_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Vosedesz.A"
        threat_id = "2147978709"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Vosedesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4c 24 78 c6 41 10 00 44 0f 11 7c 24 38 44 0f 11 7c 24 48 48 8b 44 24 30 e8 [0-17] 48 89 4c 24 38 48 89 44 24 40 8b 44 24 2c e8 [0-17] 48 89 4c 24 48 48 89 44 24 50}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 08 48 b9 73 69 6f 6e 20 6b 65 79 48 89 48 03 48 b9 20 72 6f 74 61 74 65 64 48 89 48 0b 48 8b 8c 24 80 00 00 00 48 c7 41 20 13 00 00 00 48 c7 41 28 13 00 00 00 83 3d ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

