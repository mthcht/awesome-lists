rule VirTool_Win64_Mecresz_A_2147978286_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Mecresz.A"
        threat_id = "2147978286"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mecresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 11 44 24 50 0f 11 44 24 40 4c 89 7c 24 38 48 c7 44 24 60 00 00 00 00 c7 44 24 30 01 00 00 00 c7 44 24 28 03 00 00 00 c7 44 24 20 01 00 00 00 48 89 d9 48 89 fa 4d 89 f0 41 b9 ff 01 0f 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 74 24 60 48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 48 89 f1 ba 00 00 00 40 41 b8 04 00 00 00 45 31 c9 e8 ?? ?? ?? ?? 48 ff c8 48 83 f8 fd ?? ?? 48 89 f1 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {56 57 48 83 ec 68 48 89 ce e8 ?? ?? ?? ?? 48 89 c7 e8 ?? ?? ?? ?? 31 c7 81 e7 ff ff ff 00 48 89 7c 24 28 ?? ?? ?? ?? ?? 48 89 f9 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

