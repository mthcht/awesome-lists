rule VirTool_Win32_Shadeloadesz_A_2147917415_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Shadeloadesz.A!MTB"
        threat_id = "2147917415"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Shadeloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 ff b5 f4 fb ff ff 56 53 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 8b 85 b0 fb ff ff 33 c9 8b 00 03 85 f0 fb ff ff 0f 92 c1 f7 d9 0b c8 51 57 ?? ?? ?? ?? ?? ?? 8b c8 83 c4 08 85 c9 ?? ?? 8b 85 b0 fb ff ff 8b f9 ff b5 f0 fb ff ff 56 8b 00 03 c1 50}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 00 ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? 6a 00 [0-23] 32 c0 8b 4d f4 64 89 0d 00 00 00 00 59 8b 4d f0 33 cd}  //weight: 1, accuracy: Low
        $x_1_3 = {56 51 8b 0d 14 51 40 00 [0-16] 83 c4 04 8b c8 ?? ?? ?? ?? ?? ?? 8b c8 ?? ?? ?? ?? ?? ?? 8b c8 ?? ?? ?? ?? ?? ?? 6a 00 57 53 56 ff 75 a0 [0-22] 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c4 04 8b c8 ?? ?? ?? ?? ?? ?? f3 0f 7e 05 d0 53 40 00 33 c9 a1 d8 53 40 00 66 0f d6 44 24 14 89 44 24 1c 85 ff ?? ?? bb 0b 00 00 00 ?? ?? ?? 8b c1 33 d2 f7 f3 8a 44 14 14 30 04 0e 41 3b cf}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 00 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 51 8b 0d 14 51 40 00 [0-16] 83 c4 04 8b c8 [0-16] c7 44 24 10 00 00 00 00 ?? ?? ?? ?? ?? 8b f0 85 f6 ?? ?? ?? ?? ?? ?? 8b 7c 24 10 85 ff [0-17] 57 51 8b 0d 14 51 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

