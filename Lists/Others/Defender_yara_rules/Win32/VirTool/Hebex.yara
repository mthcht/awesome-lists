rule VirTool_Win32_Hebex_A_2147918048_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Hebex.A!MTB"
        threat_id = "2147918048"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Hebex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0d 64 30 40 00 [0-21] 8b c8 ?? ?? ?? ?? ?? ?? 0f 10 05 fc 35 40 00 33 c0 c7 45 c4 2c 59 ec 8c 89 45 d8 ?? ?? ?? 50 ?? ?? ?? c7 45 c8 a1 07 d9 11 50 6a 01 6a 00 ?? ?? ?? c7 45 cc b1 5e 00 0d 50 c7 45 d0 56 bf e6 ee c7 45 d4 3c 03 00 00 c7 45 dc c0 00 00 00 c7 45 e0 00 00 00 46 0f 11 45 b4}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 8c 8d ?? ?? 52 ?? ?? ?? ?? ?? 50 8b 08 ?? ?? 8b f0 85 f6 ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 88 8b 75 80 6a 01 6a 00 8b 08 56 50 ?? ?? ?? 8b 0d 64 30 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 75 e8 ba ?? ?? ?? ?? 89 75 80 ?? ?? ?? ?? ?? 8b d7 8b c8 ?? ?? ?? ?? ?? 8b c8 ?? ?? ?? ?? ?? ?? 8b 06 57 56 ?? ?? ?? 8b f0 85 f6}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 ec 00 00 00 00 6a 00 89 45 e4 ?? ?? ?? 8b 45 8c 6a 17 6a 00 52 8b 08 50 ?? ?? ?? 8b 0d 64 30 40 00 8b f0 ?? ?? ?? ?? ?? 85 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

