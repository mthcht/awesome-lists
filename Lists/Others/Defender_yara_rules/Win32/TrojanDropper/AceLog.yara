rule TrojanDropper_Win32_AceLog_A_2147767192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/AceLog.A!dha"
        threat_id = "2147767192"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "AceLog"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 4d 5a 00 00 66 39 03 74 10 68 c1 00 00 00 ff ?? ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 43 3c 81 3c 03 50 45 00 00 75 ?? 2b 73 1c 83 7b 20 00 89 b5 ?? ?? ?? ?? 74 ?? 8b 73 20 2b 73 1c 89 b5}  //weight: 2, accuracy: Low
        $x_2_2 = {52 00 55 00 4e 00 44 00 4c 00 ?? 00 33 00 32 00 2e 00 45 00 58 00 45 00 20 00 22 00 25 00 73 00 22 00 2c 00 20 00 23 00 31 00 00 00 63 6d 64 20 2f ?? 20 44 45 4c 20 00 20 22 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {54 00 65 00 72 00 6d 00 53 00 72 ?? 76 00 43 00 6c 00 74 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {52 00 75 00 6e 00 54 00 69 00 6d 00 65 ?? 42 00 72 00 6f 00 6b 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {6c 00 61 00 6b 00 73 00 6a ?? 64 00 68 00 66 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 00 75 00 6e 00 54 00 69 00 6d 00 65 ?? 42 00 72 00 6f 00 6b 00 2e 00 6c 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_AceLog_B_2147780963_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/AceLog.B!dha"
        threat_id = "2147780963"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "AceLog"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 4d 5a 00 00 83 c4 04 66 39 07 74 ?? 68 c1 00 00 00 ff 15 [0-48] 8b 47 3c 81 3c 07 50 45 00 00 75 ?? 8b 47 1c 8b b5 ?? ?? ?? ?? 8b 4f 20 2b f0 85 c9 74 04 8b f1 2b f0 53 56 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 4f 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_AceLog_B_2147780963_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/AceLog.B!dha"
        threat_id = "2147780963"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "AceLog"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 83 c0 08 3d 00 01 00 00 72 b6}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 84 0d ?? ?? ff ff 66 31 84 0d ?? ?? ff ff 0f b7 84 0d ?? ?? ff ff 66 31 84 0d ?? ?? ff ff 0f b7 84 0d ?? ?? ff ff 66 31 84 0d ?? ?? ff ff 0f b7 84 0d ?? ?? ff ff 66 31 84 0d ?? ?? ff ff 83 c1 08 81 f9 00 01 00 00 72 b5}  //weight: 1, accuracy: Low
        $x_10_3 = {63 6d 64 20 2f ?? 20 44 45 4c 20 00 20 22 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

