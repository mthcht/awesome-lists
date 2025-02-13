rule VirTool_Win32_PipImpos_A_2147788329_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/PipImpos.A!MTB"
        threat_id = "2147788329"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PipImpos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 18 8b 4c 24 1c 6a 00 6a 00 6a 10 89 44 24 34 8d ?? ?? ?? 50 6a 00 ff 74 24 24 c7 44 24 3c 01 00 00 00 89 4c 24 44 c7 44 24 48 02 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 8d ?? ?? ?? 50 68 40 16 40 00 6a 00 6a 00 ff ?? 68 20 4e 00 00 50 ff ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {89 74 24 1c e8 ?? ?? ?? ?? 83 c4 0c 8d ?? ?? ?? 50 68 00 01 00 00 68 50 e4 41 00 6a 02 56 ff 15 ?? ?? ?? ?? 68 00 00 06 00 6a 00 68 50 e4 41 00 ff 15 ?? ?? ?? ?? 50 89 44 24 24 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {68 81 00 06 00 6a 00 6a 00 68 50 b4 41 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c4 04 8d ?? ?? ?? 6a 00 50 68 ff 00 00 00 8d ?? ?? ?? ?? ?? ?? 50 56 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_6 = {64 a3 00 00 00 00 89 55 bc 89 4d ac 33 ff 89 7d a8 33 c0 89 45 b0 89 45 a4 33 db 89 5d a0 89 45 b8 33 f6 89 75 b4 c7 45 e0 04 00 00 00 89 45 fc 8d ?? ?? 50 56 56 8d ?? ?? 50 51 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

