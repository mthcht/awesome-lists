rule Trojan_Win32_Pasich_A_2147607327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pasich.A"
        threat_id = "2147607327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pasich"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {85 c9 76 0f 80 34 30 ?? 8b 4c 24 ?? 83 c0 01 3b c1 72 f1 [0-1] 8d 44 24 10 50 6a 00 6a 01}  //weight: 6, accuracy: Low
        $x_2_2 = {c7 46 04 78 74 43 78 89 0e 89 74 24 1c ff 15 ?? ?? ?? ?? 85 c0 75 15}  //weight: 2, accuracy: Low
        $x_2_3 = {81 78 04 78 74 43 78 0f 95 c2 83 ea 01 23 d0}  //weight: 2, accuracy: High
        $x_1_4 = {5b 72 65 66 65 72 65 72 5f 65 6e 64 5d 00}  //weight: 1, accuracy: High
        $x_1_5 = {5b 6a 73 5f 69 6e 6a 65 63 74 5f 65 6e 64 5d 00}  //weight: 1, accuracy: High
        $x_1_6 = {3f 6d 6f 64 65 3d 67 65 6e 26 00}  //weight: 1, accuracy: High
        $x_1_7 = {5b 50 41 4e 45 4c 5f 53 49 47 4e 5f 43 48 45 43 4b 5d 00}  //weight: 1, accuracy: High
        $x_1_8 = {63 6c 62 49 6d 61 67 65 44 61 74 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

