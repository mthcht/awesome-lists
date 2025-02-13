rule Backdoor_Win32_Yonsole_A_2147633733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Yonsole.A"
        threat_id = "2147633733"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Yonsole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 05 08 00 00 77 ?? 74 ?? 8b c8 83 e9 02 74 ?? 81 e9 02 08 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {75 11 8b 45 10 8b 4d 1c 03 c1 89 84 24}  //weight: 1, accuracy: High
        $x_1_3 = {7e 1f 8b 4c 24 04 8a 14 31 80 c2 ?? 88 14 31 8b 4c 24 04 8a 14 31 80 f2 ?? 88 14 31 46 3b f0 7c e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Yonsole_B_2147633734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Yonsole.B"
        threat_id = "2147633734"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Yonsole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 0c 8a 06 32 c2 02 c2 88 06 46 49 75 f4}  //weight: 1, accuracy: High
        $x_10_2 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 3d 3d 3d}  //weight: 10, accuracy: High
        $x_1_3 = {83 c0 fd 83 f8 36 0f 87}  //weight: 1, accuracy: High
        $x_1_4 = {3d 03 02 00 00 0f 87 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 3d 05 01 00 00 77 ?? 74 ?? 2d 00 01 00 00 74 0c 48 74 ?? 83 e8 03 0f 85}  //weight: 1, accuracy: Low
        $x_1_5 = {47 65 74 50 6c 75 67 69 6e 52 65 73 75 6c 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

