rule VirTool_Win32_Shelesz_A_2147957267_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Shelesz.A"
        threat_id = "2147957267"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 51 68 00 08 00 00 ff 75 c0 ?? ?? ?? ?? ?? ?? 85 f6 ?? ?? 2b fe 81 ff 00 10 00 00 ?? ?? 8b 4e fc 83 c7 23 2b f1 ?? ?? ?? 83 f8 1f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 d0 8b 4d d0 83 c1 76 33 4c 85 cc 8b 45 d0 89 4c 85 cc 8b 45 d0 40 89 45 d0 83 7d d0 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Shelesz_A_2147957267_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Shelesz.A"
        threat_id = "2147957267"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4e 0c 89 86 78 04 00 00 89 be 7c 04 00 00 89 fa 89 9e 80 04 00 00 89 8e 84 04 00 00 ?? ?? ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 58 [0-33] 89 5e 50 89 86 d8 00 00 00 31 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 04 89 44 24 08 6a 04 68 73 d5 4b 00 6a 0b e8 ?? ?? ?? ?? 83 c4 0c 31 c0 39 c6 ?? ?? 8b 54 24 08}  //weight: 1, accuracy: Low
        $x_1_3 = {50 6a 40 56 53 e8 ?? ?? ?? ?? 8b 74 24 04 85 c0 ?? ?? 89 f1 ba ?? ?? ?? ?? 6a 04 68 73 d5 4b 00 6a 21 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

