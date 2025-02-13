rule VirTool_Win32_Hitijekt_A_2147823372_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Hitijekt.A!MTB"
        threat_id = "2147823372"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitijekt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 48 8b 04 25 30 00 00 00 48 89 45 48 48 8b 45 48 48 8b 40 60 48 89 45 68 48 8b 45 68 48 8b 40 10 48 89 85 88 00 00 00 48 8b 85 88 00 00 00 48 63 40 3c 48 8b 8d 88 00 00 00 48 03 c8 48 8b c1 48 89 85 a8 00 00 00 b8 08 00 00 00 48 6b c0 01 48 8b 8d a8 00 00 00 48 8d ?? ?? ?? ?? ?? ?? 48 89 85 c8 00 00 00 48 8b 85 c8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 85 88 01 00 00 48 8b 00 48 8b 8d 88 00 00 00 48 03 c8 48 8b c1 48 89 85 e8 01 00 00 48 8b 85 e8 01 00 00 41 b8 02 00 00 00 48 8b d0 48 8b 8d 88 02 00 00 e8 ?? ?? ?? ?? 48 8b 85 88 02 00 00 48 83 c0 02 48 89 85 88 02 00 00 48 c7 85 28 01 00 00 08 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 83 f8 01 0f 84 ?? ?? ?? ?? 48 8b 85 28 01 00 00 48 8b 8d 88 01 00 00 48 03 c8 48 8b c1 48 89 85 88 01 00 00 48 8b 85 88 01 00 00 48 83 38 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 85 44 02 00 00 ff c0 89 85 44 02 00 00 8b 45 24 39 85 44 02 00 00 0f 8d ?? ?? ?? ?? 48 63 85 44 02 00 00 48 8b 4d 08 48 8b 04 c1 48 89 85 68 01 00 00 48 8b 85 68 01 00 00 8b 00 48 8b 8d 88 00 00 00 48 03 c8 48 8b c1 48 89 85 88 01 00 00 48 c7 85 28 01 00 00 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Hitijekt_B_2147823373_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Hitijekt.B!MTB"
        threat_id = "2147823373"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitijekt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f2 48 0f 2c c8 48 03 c8 48 8b c1 48 8b 8d 10 01 00 00 48 89 01 48 8b 85 10 01 00 00 48 8b 00 48 d1 e0 48 89 85 d8 00 00 00 ff 15 ?? ?? ?? ?? 48 8b 8d d8 00 00 00 4c 8b c1 ba 08 00 00 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 89 45 08 48 83 7d 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 85 98 01 00 00 48 89 85 b8 01 00 00 48 8b 85 b8 01 00 00 48 63 40 3c 48 8b 8d 98 01 00 00 48 03 c8 48 8b c1 48 89 85 d8 01 00 00 b8 08 00 00 00 48 6b c0 00 48 8b 95 98 01 00 00 48 8b 8d d8 01 00 00 8b 8c 01 88 00 00 00 e8 ?? ?? ?? ?? 8b c0 48 8b 8d 98 01 00 00 48 03 c8 48 8b c1 48 89 85 f8 01 00 00 48 8b 85 f8 01 00 00 8b 40 18 89 85 14 02 00 00 8b 45 04 ff c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 63 85 c4 02 00 00 48 6b c0 38 48 8b 0d ab 50 01 00 8b 44 01 18 39 85 e4 02 00 00 0f 8d ?? ?? ?? ?? 48 8b 85 68 05 00 00 48 8b 8d 88 01 00 00 48 8d ?? ?? 48 89 85 38 05 00 00 48 8b 85 88 01 00 00 48 ff c0 48 89 85 88 01 00 00 48 8b 85 a8 02 00 00 41 b8 02 00 00 00 48 8b 95 38 05 00 00 48 8b c8 e8 ?? ?? ?? ?? 48 63 85 c4 02 00 00 48 6b c0 38 48 63 8d e4 02 00 00 48 8b 15 3c 50 01 00 48 8b 44 02 08 48 8b 0c c8 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {48 c7 45 08 00 00 00 00 48 c7 45 28 00 00 00 00 48 c7 45 48 00 00 00 00 48 c7 45 68 00 00 00 00 b8 08 00 00 00 48 6b c0 01 48 8d ?? ?? 48 8b 8d 18 02 00 00 48 8b 0c 01 e8 ?? ?? ?? ?? 48 89 85 88 00 00 00 48 83 bd 88 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

