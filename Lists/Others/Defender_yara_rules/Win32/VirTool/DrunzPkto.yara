rule VirTool_Win32_DrunzPkto_A_2147773360_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DrunzPkto.A!MTB"
        threat_id = "2147773360"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DrunzPkto"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 1c a1 00 70 00 10 33 c5 89 45 fc 53 8d ?? ?? 8b d9 50 68 f8 51 00 10 6a 00 ff 15 ?? ?? ?? ?? 85 c0 74 4f 8b 45 f4 6a 00 6a 00 89 45 e8 8b 45 f8 6a 10 89 45 ec 8d ?? ?? 50 6a 00 53 c7 45 e4 01 00 00 00 c7 45 f0 02 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 1e ff 15 ?? ?? ?? ?? 3d 14 05 00 00 74 11 33 c0 5b 8b 4d fc 33 cd e8 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {50 68 f0 51 00 10 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 8d ?? ?? ?? ?? ?? ?? 50 ff 74 24 50 ff 15 ?? ?? ?? ?? 85 c0 75 19 b8 06 ?? ?? ?? 5f 5e 8b 8c 24 b4 02 00 00 33 cc e8 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {50 53 ff 75 f4 57 56 ff 15 ?? ?? ?? ?? 6a 00 85 c0 75 37 56 ff 15 ?? ?? ?? ?? 68 e8 03 00 00 56 ff 15 ?? ?? ?? ?? 56 8b 35 50 50 00 10 ff ?? ff 75 e8 ff ?? 5f 5e b8 0d 00 00 00 5b 8b 4d fc 33 cd e8 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_4 = {55 8b ec 83 ec 1c a1 00 70 00 10 33 c5 89 45 fc f3 0f 6f 45 08 53 56 57 6a 40 68 00 10 00 00 8b da 66 0f 7e c6 53 6a 00 56 89 4d f4 f3 0f 7f 45 e4 c7 45 f8 00 00 00 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff 75 36 50 56 ff 15 ?? ?? ?? ?? 68 e8 03 00 00 56 ff 15 ?? ?? ?? ?? 56 8b 35 50 50 00 10 ff ?? ff 75 e8 ff ?? 8d ?? ?? 5f 5e 5b 8b 4d fc 33 cd e8 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 00 6a 00 57 6a 00 6a 00 56 ff 15 ?? ?? ?? ?? 85 c0 75 38 50 56 ff 15 ?? ?? ?? ?? 68 e8 03 00 00 56 ff 15 ?? ?? ?? ?? 56 8b 35 50 50 00 10 ff ?? ff 75 e8 ff ?? 5f 5e b8 0e 00 00 00 5b 8b 4d fc 33 cd e8 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

