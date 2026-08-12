rule VirTool_Win64_Sentinesz_A_2147976039_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Sentinesz.A"
        threat_id = "2147976039"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sentinesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 57 41 56 41 55 53 48 83 ec 58 ba 06 00 00 00 41 b8 0e 00 00 00 [0-16] 4c 89 f9 e8 [0-17] 4c 89 f1 c7 44 24 4a b8 57 00 07 66 c7 44 24 4e 80 c3 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b8 01 00 00 00 4c 89 fa 4c 89 e1 e8 ?? ?? ?? ?? 80 3b 00 89 c6 ?? ?? 41 b8 0f 00 00 00 ?? ?? ?? ?? ?? ?? ?? 4c 89 e1 e8 ?? ?? ?? ?? 80 3b 00 4c 8b 74 24 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

