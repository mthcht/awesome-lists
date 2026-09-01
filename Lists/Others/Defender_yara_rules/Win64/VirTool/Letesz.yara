rule VirTool_Win64_Letesz_A_2147977309_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Letesz.A"
        threat_id = "2147977309"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Letesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 68 66 44 0f d6 7c 24 60 48 89 44 24 78 c6 44 24 2f 00 48 8b 40 60 e8 ?? ?? ?? ?? 48 b9 00 b8 64 d9 45 00 00 00 48 01 c8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 28 48 89 5c 24 30 ?? ?? ?? ?? ?? ?? ?? bb 21 00 00 00 ?? ?? ?? ?? ?? bf 01 00 00 00 48 89 fe e8 ?? ?? ?? ?? 31 c0 48 83 c4 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

