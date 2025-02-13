rule VirTool_Win32_Conjecture_A_2147762341_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Conjecture.A"
        threat_id = "2147762341"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Conjecture"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 8c 24 08 02 00 00 48 8b 14 01 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 08 00 00 00 48 6b c0 03 48 8b 8c 24 08 02 00 00 48 8b 0c 01 e8 ?? ?? ?? ?? 48 ff c0 48 89 44 24 58 48 8b 44 24 58 48 d1 e0 48 8b c8 e8 ?? ?? ?? ?? 48 89 84 24 a0 00 00 00 b8 08 00 00 00 48 6b c0 03 48 c7 44 24 20 ff ff ff ff 48 8b 8c 24 08 02 00 00 4c 8b 0c 01 4c 8b 44 24 58 48 8b 94 24 a0 00 00 00 48 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 8c 24 a0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b c0 33 d2 b9 ff ff 1f 00 ff 15 ?? ?? ?? ?? 48 89 84 24 c0 00 00 00 41 b8 70 00 00 00 33 d2 48 8d ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? ?? 45 33 c0 ba 01 00 00 00 33 c9 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 4c 8b 84 24 a8 00 00 00 33 d2 48 8b c8 ff 15 ?? ?? ?? ?? 48 89 84 24 58 01 00 00 4c 8d ?? ?? ?? ?? ?? ?? 45 33 c0 ba 01 00 00 00 48 8b 8c 24 58 01 00 00 ff 15 ?? ?? ?? ?? 48 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 08 00 00 00 4c 8d ?? ?? ?? ?? ?? ?? 41 b8 00 00 02 00 33 d2 48 8b 8c 24 58 01 00 00 ff 15 ?? ?? ?? ?? c7 84 24 f0 00 00 00 70 00 00 00 b8 08 00 00 00 48 6b c0 05 b9 08 00 00 00 48 6b c9 04}  //weight: 1, accuracy: Low
        $x_1_3 = {45 33 c0 48 8b 94 24 d8 00 00 00 48 8b 8c 24 b0 00 00 00 ff 15 ?? ?? ?? ?? 48 8b 8c 24 d8 00 00 00 ff 15 ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {48 63 05 58 d6 01 00 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 4c 8b c0 33 d2 48 8b 8c 24 d0 00 00 00 ff 15 ?? ?? ?? ?? 48 89 84 24 b0 00 00 00 48 c7 84 24 c8 00 00 00 00 00 00 00 48 63 05 1c d6 01 00 48 8b 8c 24 c8 00 00 00 48 89 4c 24 20 4c 8b c8 4c 8b 44 24 70 48 8b 94 24 b0 00 00 00 48 8b 8c 24 d0 00 00 00 ff 15 ?? ?? ?? ?? 89 44 24 50 83 7c 24 50 00 75 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Conjecture_A_2147762342_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Conjecture.A!MTB"
        threat_id = "2147762342"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Conjecture"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 85 64 ff ff ff c7 85 54 ff ff ff 00 00 00 00 8b 8d 54 ff ff ff 51 8b 15 28 b6 41 00 52 8b 45 84 50 8b 8d 64 ff ff ff 51 8b 95 44 ff ff ff 52 ff 15 ?? ?? ?? ?? 89 45 8c 83 7d 8c 00 ?? ?? ff 15 ?? ?? ?? ?? 50 68 18 a3 41 00 e8 ?? ?? ?? ?? 83 c4 08}  //weight: 1, accuracy: Low
        $x_1_2 = {68 3c a3 41 00 e8 ?? ?? ?? ?? 83 c4 04 6a 00 8b 85 48 ff ff ff 50 8b 8d 64 ff ff ff 51 ff 15 ?? ?? ?? ?? 8b 95 48 ff ff ff 52 ff 15 ?? ?? ?? ?? 8b 85 48 ff ff ff 50}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 0c 8b 0c 10 51 68 6c a2 41 00 e8 ?? ?? ?? ?? 83 c4 08 ba 04 00 00 00 6b c2 03 8b 4d 0c 8b 14 01 52 e8 ?? ?? ?? ?? 83 c4 04 83 c0 01}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 0c 8b 0c 10 51 ba 04 00 00 00 c1 e2 02 8b 45 0c 8b 0c 10 51 ff 15 ?? ?? ?? ?? 89 45 8c 83 7d 8c 00 ?? ?? ff 15 ?? ?? ?? ?? 50 68 c8 a2 41 00 e8 ?? ?? ?? ?? 83 c4 08 ba 04 00 00 00 c1 e2 02 8b 45 0c 8b 0c 10 51 68 e8 a2 41 00 e8 ?? ?? ?? ?? 83 c4 08 6a 40 68 00 30 00 00 8b 15 28 b6 41 00 52 6a 00 8b 85 44 ff ff ff 50 ff 15 ?? ?? ?? ?? 89 85 64 ff ff ff c7 85 54 ff ff ff 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

