rule Trojan_Win32_Stoberox_A_2147651091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stoberox.A"
        threat_id = "2147651091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stoberox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 7b aa b9 24 00 00 00 51 52 b9 0a 00 00 00 0f 31 69 c0 0d 66 19 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 a1 30 00 00 00 f7 40 68 70 00 00 00 74 02 ff e0 c3}  //weight: 1, accuracy: High
        $x_1_3 = {03 7f 3c 0f b7 4f 16 83 7d 0c 00 74 08 81 f1 00 20 00 00 eb 06 81 c9 00 20 00 00 66 89 4f 16}  //weight: 1, accuracy: High
        $x_1_4 = {c1 e9 02 f3 a5 0f b7 53 06 8d 83 f8 00 00 00 8b 48 10 8b 70 14 8b 78 0c 03 75 e8 03 7d e0 f3 a4 83 c0 28 4a 75 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Stoberox_B_2147672221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stoberox.B"
        threat_id = "2147672221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stoberox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d ff ff 00 00 75 ?? 8b 3f 8b 47 28 83 f8 64 73 02 eb ?? 51 51}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d fc 8b 77 3c 85 f6 74 ?? 33 d2 66 ad 84 c0 74 11 3c 41 72 06 3c 5a 77 02 0c 20 c1 c2 03 32 d0 eb e9 8b 75 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

