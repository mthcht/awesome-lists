rule VirTool_Win32_HookGina_A_2147638854_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/HookGina.A"
        threat_id = "2147638854"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "HookGina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 c6 44 24 ?? 64 c6 44 24 ?? 4f c6 44 24 ?? 75 c6 44 24 ?? 74}  //weight: 1, accuracy: Low
        $x_2_2 = {8a 14 01 88 10 40 4e 75 f7}  //weight: 2, accuracy: High
        $x_1_3 = {0d 00 0a 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 20 00 20 00 3d 00 20 00 25 00 73 00 20 00 0d 00 0a 00 50 00 61 00 73 00 73 00 20 00 20 00 20 00 20 00 3d 00 20 00 25 00 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 48 6f 6f 6b 6d 73 67 69 6e 61 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_2_5 = {89 45 f4 83 7d f4 05 7d 13 8b 4d f8 03 4d f4 8b 55 f4 8a 82 ?? ?? ?? ?? 88 01 eb de}  //weight: 2, accuracy: Low
        $x_1_6 = {55 00 73 00 65 00 72 00 4e 00 61 00 6d 00 65 00 3d 00 25 00 6c 00 73 00 0d 00 0a 00 50 00 61 00 73 00 73 00 57 00 6f 00 72 00 64 00 3d 00 25 00 6c 00 73 00 0d 00 0a 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 3d 00 25 00 6c 00 73 00 0d 00 0a 00 4f 00 6c 00 64 00 50 00 61 00 73 00 73 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 25 00 6c 00 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_HookGina_B_2147689726_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/HookGina.B"
        threat_id = "2147689726"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "HookGina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 00 e9 00 00 00 00 00 03 00 8b ff 55}  //weight: 1, accuracy: Low
        $x_1_2 = {55 00 73 00 65 00 72 00 20 00 20 00 20 00 20 00 3d 00 20 00 25 00 73 00 20 00 0d 00 0a 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 20 00 20 00 3d 00 20 00 25 00 73 00 20 00 0d 00 0a 00 50 00 61 00 73 00 73 00 20 00 20 00 20 00 20 00 3d 00 20 00 25 00 73 00 20 00 0d 00 0a 00 4f 00 6c 00 64 00 50 00 61 00 73 00 73 00 20 00 3d 00 20 00 25 00 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 64 2f 25 64 2f 25 64 2f 25 64 3a 25 64 3a 25 64 00 57 6c 78 4c 6f 67 67 65 64 4f 75 74 53 41 53 00 6d 73 67 69 6e 61 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_4 = {8d 44 24 04 50 6a 40 6a 05 51 c7 44 24 14 00 00 00 00 ff d6 0f b6 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 10 0f b6 0d ?? ?? ?? ?? 88 48 01 0f b6 15 ?? ?? ?? ?? 88 50 02 0f b6 0d ?? ?? ?? ?? 88 48 03 0f b6 15 ?? ?? ?? ?? 88 50 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

