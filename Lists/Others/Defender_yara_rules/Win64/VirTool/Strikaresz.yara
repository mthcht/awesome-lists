rule VirTool_Win64_Strikaresz_A_2147919483_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Strikaresz.A!MTB"
        threat_id = "2147919483"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Strikaresz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 95 c0 02 00 00 48 89 95 d0 02 00 00 31 c0 89 c1 41 b8 00 30 00 00 41 b9 04 00 00 00 ?? ?? ?? ?? ?? 48 89 45 e0 ?? ?? 48 8b 45 e0 48 89 85 28 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 55 c8 48 8b 4d e0 41 b8 20 00 00 00 [0-18] 89 45 c4 ?? ?? 8b 45 c4 89 85 30 02 00 00 83 f8 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 45 e0 c7 85 0c 02 00 00 00 00 00 00 48 89 85 38 02 00 00 48 c7 85 88 02 00 00 00 00 00 00 48 c7 85 ?? 02 00 00 00 00 00 00 48 89 85 10 02 00 00 48 c7 85 98 02 00 00 00 00 00 00 48 c7 85 a0 02 00 00 00 00 00 00 4c 8b 85 10 02 00 00 48 89 e0 ?? ?? ?? ?? ?? ?? ?? 48 89 48 28 c7 40 20 00 00 00 00 31 c0 41 89 c1 4c 89 c9 4c 89 ca}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 4d f8 ?? ?? ?? ?? ?? 48 89 55 e8 48 89 45 f0 ?? ?? 48 8b 45 e8 48 8b 4d f0 48 89 8d b8 02 00 00 48 89 85 c0 02 00 00 48 83 bd b8 02 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

