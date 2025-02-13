rule VirTool_Win64_Paloadesz_A_2147853086_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Paloadesz.A!MTB"
        threat_id = "2147853086"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Paloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b cc 44 8b c8 e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 4c ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 78 6e 74 64 6c c7 45 7c 6c 2e 64 6c 66 c7 85 80 00 00 00 6c 00 c7 85 c8 00 00 00 4e 74 54 72 c7 85 cc 00 00 00 61 63 65 43 c7 85 d0 00 00 00 6f 6e 74 72 66 c7 85 d4 00 00 00 6f 6c 44 88 a5 d6 00 00 00 ff 15 ?? ?? ?? ?? 48 8b c8 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 4c 8b e0 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 01 ff ?? ?? 45 33 c9 33 d2 41 b8 ff ff ff ff 49 8b cd ff 15 ?? ?? ?? ?? 48 ?? ?? ?? c7 45 58 6b 65 72 6e 48 89}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 89 ac 24 10 11 00 00 40 88 7d a8 ff 15 ?? ?? ?? ?? 48 8b c8 48 ?? ?? ?? ff 15 ?? ?? ?? ?? 48 89 7c 24 38 41 b8 50 00 00 00 89 7c 24 30 45 33 c9 c7 44 24 28 03 00 00 00 48 8b}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 45 68 61 6d 73 69 c7 45 6c 2e 64 6c 6c c6 45 70 00 c7 85 d8 00 00 00 41 6d 73 69 c7 85 dc 00 00 00 53 63 61 6e c7 85 e0 00 00 00 42 75 66 66 66 c7 85 e4 00 00 00 65 72 c6 85 e6 00 00 00 00 ff 15 ?? ?? ?? ?? 48 ?? ?? ?? ff 15 ?? ?? ?? ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

