rule VirTool_Win64_Revehesz_A_2147980692_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Revehesz.A"
        threat_id = "2147980692"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Revehesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 48 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 40 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 08 c7 44 24 20 01 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 b9 00 00 00 00 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 85 80 10 00 00 68 00 00 00 c7 85 bc 10 00 00 00 01 00 00 48 8b 85 10 11 00 00 48 89 85 d8 10 00 00 48 8b 85 10 11 00 00 48 89 85 e0 10 00 00 [0-33] 49 89 c8 48 89 c1 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {89 45 fc 66 0f ef c9 f2 0f 2a 4d fc f2 0f ?? ?? ?? ?? ?? ?? f2 0f 58 c1 f2 0f 11 45 d0 f2 0f ?? ?? ?? ?? ?? ?? f2 0f 11 45 e0 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

