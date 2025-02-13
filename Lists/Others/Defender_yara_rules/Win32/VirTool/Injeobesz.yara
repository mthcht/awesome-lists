rule VirTool_Win32_Injeobesz_A_2147918049_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injeobesz.A!MTB"
        threat_id = "2147918049"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injeobesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 56 57 ff ?? ff b5 84 fe ff ff ff b5 5c fe ff ff ?? ?? ?? ?? ?? ?? 6a 00 6a 00 6a 00 56 6a 00 6a 00 57 ?? ?? 8b f0 85 f6 ?? ?? 68 f4 01 00 00 56 ?? ?? ?? ?? ?? ?? 56}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 83 f9 0e 0f 45 d1 [0-18] 30 04 37 83 fa 0d ?? ?? ?? ?? ?? ?? 0f 45 c8 0f b6 01 b9 01 00 00 00 30 44 37 01}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 01 00 00 00 30 46 fd 83 fa 0d ?? ?? ?? 0f 45 c8 83 bd bc fe ff ff 00 ?? ?? ?? ?? ?? ?? 8b 85 84 fe ff ff 57 ff b5 5c fe ff ff c6 40 12 00 ?? ?? ?? ?? ?? ?? 8b bd 50 fe ff ff 6a 40 68 00 10 00 00 6a 19 6a 00 57 ?? ?? ff b5 88 fe ff ff 8b f0 ff b5 5c fe ff ff ?? ?? ?? ?? ?? ?? 6a 00 6a 19}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 85 58 fe ff ff 8b 36 8b 40 0c 83 c0 0c 3b f0 ?? ?? 85 d2 ?? ?? ?? ?? ?? ?? 68 b0 b1 00 00 [0-16] 83 c4 08 68 b0 b1 00 00 6a 00 68 3a 04 00 00 ?? ?? ?? ?? ?? ?? 89 85 50 fe ff ff 85 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {89 95 8c fe ff ff 0f b6 01 b9 01 00 00 00 30 47 fd 83 fe 0d ?? ?? ?? 0f 45 c8 85 d2 ?? ?? ?? ?? ?? ?? 8b bd 84 fe ff ff 8b 8d bc fe ff ff 88 57 0c 8b 95 88 fe ff ff ?? ?? ?? ?? ?? 8b 8d bc fe ff ff 8b d7 89 85 8c fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

