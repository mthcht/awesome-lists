rule TrojanDropper_Win32_Lecpetex_A_2147687804_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lecpetex.A"
        threat_id = "2147687804"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lecpetex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 72 61 77 2e 70 68 70 3f 69 3d 67 47 32 32 48 46 36 4c 00}  //weight: 2, accuracy: High
        $x_2_2 = {68 a1 a2 03 00 68 ?? ?? ?? 00 8b 55 c0 52 e8}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 45 fc 50 68 3a 77 00 00 68 ?? ?? ?? 00 e8 ?? ?? ff ff 83 c4 0c}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 45 fc 50 68 dd e3 00 00 68 ?? ?? ?? 00 e8 ?? ?? ff ff 83 c4 0c}  //weight: 2, accuracy: Low
        $x_1_5 = {68 00 f6 00 00 e8 ?? ?? ff ff 83 c4 04 8b 4d 08 03 01 8b 55 08 89 02}  //weight: 1, accuracy: Low
        $x_1_6 = {25 ff 00 00 00 33 d2 b9 0a 00 00 00 f7 f1 83 c2 30 88 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

