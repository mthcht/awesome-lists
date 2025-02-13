rule Worm_Win32_Fropjor_A_2147618407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Fropjor.A"
        threat_id = "2147618407"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Fropjor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 18 5e 8d 44 24 04 50 ff 15 ?? ?? ?? ?? 83 f8 02 75 0b 8d 44 24 04 50 e8 ?? ?? 00 00 59 fe 44 24 04 4e 75 de 68 98 3a 00 00 c6 44 24 08 63 ff 15 ?? ?? ?? ?? eb c9}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 70 3c 03 f0 0f b7 46 06 6b c0 28 57 8d bc 30 f8 00 00 00 bb ?? ?? ?? ?? 8d 47 d8 8b d3 e8 ?? ?? 00 00 85 c0 0f 84 ?? ?? 00 00 0f b7 46 06 40 53 57 66 89 46 06 e8 ?? ?? 00 00 a1 ?? ?? ?? ?? 05 d4 00 00 00 89 47 08}  //weight: 2, accuracy: Low
        $x_1_3 = {67 3d 25 64 26 73 31 3d 25 73 26 73 32 3d 25 73 26 73 33 3d 25 73 26 73 34 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {75 73 72 5c 61 6c 6c 5c 6c 6f 67 69 6e 5f 77 2e 62 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

