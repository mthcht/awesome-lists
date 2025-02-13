rule VirTool_Win64_Shadeloadesz_A_2147917414_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shadeloadesz.A!MTB"
        threat_id = "2147917414"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shadeloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d7 49 8b cf ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 8b 54 24 44 48 c7 c0 ff ff ff ff 49 03 16 48 8b ce 48 0f 42 d0 ?? ?? ?? ?? ?? ?? 48 85 c0 ?? ?? 49 8b 0e 48 8b d7 44 8b 44 24 44 48 03 c8 48 8b f0}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 44 24 28 48 89 44 24 20 45 33 c9 [0-21] 33 c9 [0-23] 32 c0 48 8b 8c 24 60 03 00 00 48 33 cc}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b c8 48 8b d7 ?? ?? ?? ?? ?? ?? 48 8b c8 [0-19] 48 8b c8 [0-19] 48 8b 4d a7 4c 8b cb 4c 8b c6 4c 89 74 24 20 48 8b d7 ?? ?? ?? ?? ?? ?? 85 c0 [0-23] 48 8b 0d 16 3b 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b c8 48 [0-18] f2 0f 10 05 cc 45 00 00 8b 05 ce 45 00 00 f2 0f 11 44 24 20 89 44 24 28 48 85 f6 ?? ?? 49 b8 [0-19] 48 8b cb 49 8b c0 48 f7 e3 48 d1 ea 48 6b c2 0b 48 2b c8 0f b6 44 0c 20 30 04 1f 48 ff c3 48 3b de}  //weight: 1, accuracy: Low
        $x_1_5 = {40 55 53 56 41 56 ?? ?? ?? ?? ?? ?? ?? ?? 48 81 ec d8 04 00 00 48 8b 05 e4 55 00 00 48 33 c4 48 89 85 c0 03 00 00 0f 57 c0 ?? ?? ?? ?? ?? 33 c0 ?? ?? ?? ?? ?? ?? ?? 48 89 45 b0 33 db ?? ?? ?? ?? 89 5c 24 40 0f 11 44 24 60 48 89 44 24 68 4c 8b f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

