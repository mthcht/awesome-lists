rule VirTool_Win64_Injesz_A_2147918047_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injesz.A!MTB"
        threat_id = "2147918047"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4d c0 ?? ?? ?? ?? 48 83 c2 10 48 89 5d b8 48 89 5c 24 20 ?? ?? ?? ?? ?? 33 d2 ?? ?? ?? ?? ?? ?? ?? 41 b8 00 10 00 00 ?? ?? ?? ?? ?? 48 8b 55 b8 ?? ?? ?? ?? ?? ?? ?? 48 8b 4d c0 41 b9 00 10 00 00 48 89 5c 24 20 ?? ?? ?? ?? ?? 48 63 85 bc 0c 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 4d c0 41 b9 00 0c 00 00 48 89 5c 24 20 8b 94 05 a8 0c 00 00 48 03 55 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 5c 24 38 f2 0f 11 45 70 0f 57 c0 48 89 5c 24 30 c7 44 24 28 04 00 00 00 89 5c 24 20 0f 11 4d c0 89 5d 08 0f 11 45 d8 0f 11 45 e8 0f 11 45 f8 ?? ?? ?? ?? ?? ?? 48 8b 4d c0}  //weight: 1, accuracy: Low
        $x_1_3 = {58 48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 48 83 ec 28 8b 0d 11 3c ?? ?? ?? ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 4c 8b d1 0f 05 c3 c7 05 e4 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

