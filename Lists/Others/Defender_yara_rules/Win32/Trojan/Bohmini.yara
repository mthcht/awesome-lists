rule Trojan_Win32_Bohmini_A_2147599595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bohmini.A"
        threat_id = "2147599595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bohmini"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 48 10 03 (cb|cd) 89 0d ?? ?? 40 00 c7 42 30 ?? ?? 00 00 a1 ?? ?? 40 00 8b 0d ?? ?? 40 00 89 48 38 e8 ?? ?? ff ff 6a 00 e8 ?? ?? ff ff 8b 0d}  //weight: 5, accuracy: Low
        $x_5_2 = {75 07 53 ff 15 ?? ?? 40 00 8b 44 24 ?? 85 c0 7c 0e 3d 50 46 00 00 7f 07 ba 01 00 00 00 eb 02 33 d2 85 f6}  //weight: 5, accuracy: Low
        $x_2_3 = {68 74 74 70 3a 2f 2f 31 39 34 2e 31 32 36 2e 31 39 33 2e 31 35 37 2f 70 69 6e 67 [0-4] 2f 25 73 2f 25 64}  //weight: 2, accuracy: Low
        $x_1_4 = {25 73 20 2d 66 69 72 73 74 72 75 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {4e 65 74 53 63 68 65 64 75 6c 65 4a 6f 62 41 64 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

