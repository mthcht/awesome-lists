rule Trojan_Win32_Gonlyn_A_2147678473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gonlyn.A"
        threat_id = "2147678473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gonlyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {84 c0 75 0c 68 60 ea 00 00 e8 ?? ?? ?? ?? eb ?? 33 c0 5a 59 59 64 89 10 eb 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 50 3c 03 d0 8b c2 66 8b 40 16 66 25 00 20 66 3d 00 20 0f 94 c0 84 c0 74 1c}  //weight: 1, accuracy: High
        $x_1_3 = {56 32 6c 75 62 47 39 6e 62 32 34 75 5a 58 68 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 6d 56 6e 55 33 5a 79 4d 7a 49 75 5a 58 68 6c 00 00 00 00 4f 6e 6c 79 4f 6e 65}  //weight: 1, accuracy: High
        $x_1_5 = {64 58 42 6b 59 58 52 6c 4c 6d 31 70 59 33 4a 76 63 32 39 6d 64 43 35 6a 62 32 30 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {47 6f 6e 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 64 61 74 00}  //weight: 1, accuracy: Low
        $x_2_7 = {61 48 52 30 63 44 6f 76 4c 77 3d 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3a 34 34 33 2f 3f}  //weight: 2, accuracy: Low
        $x_1_8 = {4f 6e 6c 79 4f 6e 65 4c 57 4b 4b 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

