rule VirTool_Win32_BruterShell_A_2147899112_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BruterShell.A"
        threat_id = "2147899112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BruterShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 78 05 e8 75 ?? 80 78 06 03 75 ?? 80 78 0d 8b 75 ?? 80 78 0e d4 75 ?? 0f b6 50 02}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 04 89 4d 39 8c 89 44 24 08 e8}  //weight: 1, accuracy: High
        $x_1_3 = {89 14 24 c7 44 24 ?? 50 4f 53 54 c6 44 24 ?? 00 c7 44 24 ?? 7b 22 61 72 c7 44 24 ?? 63 68 22 3a}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 44 24 04 aa fc 0d 7c [0-128] c7 44 24 04 bd ca 3b d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_BruterShell_A_2147899112_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BruterShell.A"
        threat_id = "2147899112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BruterShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 04 26 25 19 3e 89 44 24 08 c7 04 24 00 00 00 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {80 78 05 e8 75 ?? 80 78 06 03 75 ?? 80 78 0d 8b 75 ?? 80 78 0e d4 75 ?? 0f b6 50 02}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 04 bd ca 3b d3 89 44 24 08 8b 84 24 ?? 00 00 00 89 04 24 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {89 44 24 08 c7 44 24 04 ff ff ff ff 89 3c 24 e8}  //weight: 1, accuracy: High
        $x_1_5 = {c7 44 24 04 b8 0a 4c 53 89 44 24 08 e8}  //weight: 1, accuracy: High
        $x_1_6 = {c7 44 24 04 89 4d 39 8c 89 44 24 08 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

