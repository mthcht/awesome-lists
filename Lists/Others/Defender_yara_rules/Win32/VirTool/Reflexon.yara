rule VirTool_Win32_Reflexon_A_2147818517_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Reflexon.A!MTB"
        threat_id = "2147818517"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Reflexon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 40 40 4c 8b d1 b8 66 c7 40 48 0f 05 c6 40 4a c3 89 70 44 48 83 e8 80 c7 00 4c 8b d1 b8 66 c7 40 08 0f 05 c6 40 0a c3 89 68 04 48 89 ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? c7 00 4c 8b d1 b8 66 c7 40 08 0f 05 c6 40 0a c3 89 58 04}  //weight: 1, accuracy: Low
        $x_1_2 = {81 79 40 4c 8b d1 b8 ?? ?? ff c2 41 3b d1 ?? ?? e9 ?? ?? ?? ?? 66 41 ff c0 66 45 3b c3 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 bc 24 10 01 00 00 33 ff 48 8d ?? ?? ?? ?? ?? 49 8b cf 89 7d eb 89 7d 03 0f 11 45 2f ff 15 ?? ?? ?? ?? 48 85 c0 0f 84 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? 48 8d ?? ?? c7 45 e7 30 00 00 00 0f 57 c0 48 89 45 f7}  //weight: 1, accuracy: Low
        $x_1_4 = {33 c9 ba 00 01 00 00 41 b8 00 30 00 00 44 8d ?? ?? ff 15 ?? ?? ?? ?? 48 8b c8 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Reflexon_B_2147818518_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Reflexon.B!MTB"
        threat_id = "2147818518"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Reflexon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 01 4c 8b d1 b8 4c 8d ?? ?? ?? 66 c7 41 08 0f 05 48 05 c0 00 00 00 c6 41 0a c3 41 b8 20 00 00 00 89 79 04 48 89 ?? ?? ?? ?? ?? 49 8b ca c7 00 4c 8b d1 b8 66 c7 40 08 0f 05 c6 40 0a c3 89 58 04}  //weight: 1, accuracy: Low
        $x_1_2 = {81 79 40 4c 8b d1 b8 ?? ?? ff c2 41 3b d0 ?? ?? e9 ?? ?? ?? ?? 66 41 ff c0 66 45 3b c3 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 44 24 68 48 8b d8 48 85 c0 0f 84 ?? ?? ?? ?? 33 f6 48 8d ?? ?? ?? ?? ?? 0f 57 c0 89 75 a4 48 8b c8 89 75 bc 0f 11 45 e8 ff 15 ?? ?? ?? ?? 48 85 c0 0f 84 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? 48 8d ?? ?? c7 45 a0 30 00 00 00 0f 57 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 59 44 8b 79 34 85 db 0f 84 ?? ?? ?? ?? 33 c9 ba 00 01 00 00 41 b8 00 30 00 00 44 8d ?? ?? ff 15 ?? ?? ?? ?? 4c 8b d0 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

