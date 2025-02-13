rule VirTool_Win32_Malizk_A_2147780245_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Malizk.A!MTB"
        threat_id = "2147780245"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Malizk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 57 56 53 83 ec ?? 8b 5c 24 54 8b 74 24 58 c7 44 24 2c 00 00 00 00 85 db 0f 94 c2 85 f6 0f 94 c0 08 c2 0f 85 bf 00 00 00 8b 44 24 50 85 c0 0f 84 b3 00 00 00 89 1c 24 e8 ?? ?? ?? ?? 89 c5 85 c0 0f 84 a1 00 00 00 8b 44 24 50 c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 89 74 24 08 c7 44 24 04 00 00 00 00 89 04 24 ff 15 ?? ?? ?? ?? 83 ?? ?? 89 c7 85 c0 74 6f 89 44 24 04 8b 44 24 50 c7 44 24 10 00 00 00 00 89 74 24 0c 89 5c 24 08 89 04 24 ff 15 ?? ?? ?? ?? 83 ec ?? 85 c0 74 47 8d ?? ?? ?? 8d ?? ?? c7 44 24 14 00 00 00 00 89 44 24 18 8b 44 24 5c 89 54 24 0c 89 44 24 10 8b 44 24 50 c7 44 24 08 00 00 10 00 c7 44 24 04 00 00 00 00 89 04 24 ff 15 ?? ?? ?? ?? 83 ec 1c eb 08}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 0e 00 00 00 c7 44 24 24 3c 00 00 00 f3 ab c7 44 24 08 04 01 00 00 c7 44 24 04 40 f0 40 00 c7 04 24 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec ?? c7 04 24 40 f0 40 00 ff 15 ?? ?? ?? ?? 83 ec 04 c7 44 24 08 00 00 00 00 c7 44 24 04 08 d0 40 00 89 04 24 ff 15 ?? ?? ?? ?? 83 ec ?? 8d ?? ?? ?? c7 44 24 30 1c d0 40 00 c7 44 24 34 08 d0 40 00 c7 44 24 2c 00 00 00 00 c7 44 24 40 00 00 00 00 89 04 24 ff 15 ?? ?? ?? ?? 83 ec ?? 85 c0 0f 85 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 3d ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 d0 17 40 00 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

