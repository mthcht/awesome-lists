rule VirTool_Win64_Revetesz_A_2147980267_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Revetesz.A"
        threat_id = "2147980267"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Revetesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 48 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 40 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 08 c7 44 24 20 01 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {45 31 c0 ba 01 00 00 00 ff ?? ?? ?? ?? ?? 66 0f ef c0 4c 8b 8c 24 e8 00 00 00 4c 8b 84 24 e0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {55 57 56 53 48 83 ec 48 41 b8 04 00 00 00 48 89 cb ?? ?? ?? ?? ?? 48 89 d6 e8 ?? ?? ?? ?? 48 8b 7c 24 20 48 89 f2 48 89 d9 48 8b 6c 24 30 44 8b 07 41 0f c8 45 89 c0 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

