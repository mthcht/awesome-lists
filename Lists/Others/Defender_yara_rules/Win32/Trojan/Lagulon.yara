rule Trojan_Win32_Lagulon_A_2147690387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lagulon.A"
        threat_id = "2147690387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lagulon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 72 65 70 6f 72 74 2e 74 78 74 00 5c 63 6f 6e 66 69 67 2e 62 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 64 62 52 65 70 6f 72 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {75 f6 8b c2 8d 70 01 90 8a 08 40 84 c9 75 f9 2b c6 88 4c 10 f6 8d 42 ff 8a 48 01 40 84 c9 75 f8 8b}  //weight: 1, accuracy: High
        $x_1_4 = {8b f0 8b 44 24 44 83 c4 18 3b c3 74 19 99 33 c2 2b c2 50 8d 14 37 68 ?? ?? ?? ?? 52 e8 ?? ?? ?? ?? 83 c4 0c 03 f0 33 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {8b f3 8b ca 2b f2 8a 01 88 04 0e 41 84 c0 75 f6 8b ca 8d 71 01 8a 01 41 84 c0 75 f9 2b ce 8d 7a ff 88 44 11 f6 8a 47 01 47 84 c0 75 f8 be}  //weight: 1, accuracy: High
        $x_1_6 = {41 64 6f 62 65 20 52 65 70 6f 72 74 20 53 65 72 76 69 63 65 00 00 00 00 73 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

