rule Trojan_Win32_Pramro_A_2147600633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pramro.A"
        threat_id = "2147600633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pramro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 fa 74 0f 85 2f 01 00 00 8b 45 08 03 85 e0 fe ff ff 0f be 48 06 83 f9 4f 74 16 8b 55 08 03 95 e0 fe ff ff 0f be 42 06 83 f8 6f}  //weight: 2, accuracy: High
        $x_2_2 = {6a 19 ff 15 ?? ?? 40 00 50 8b 85 ?? ?? ff ff 25 ff ff 00 00 99 b9 03 00 00 00 f7 f9 8b 14 95 ?? ?? ?? 00 52}  //weight: 2, accuracy: Low
        $x_2_3 = {c6 45 fc 01 eb 75 6a 50 ff 15 ?? ?? 40 00 50 68 ?? ?? ?? ?? 8d 8d ?? ?? ff ff e8 ?? ?? ff ff 89 85 ?? ?? ff ff 83 bd ?? ?? ff ff 00 75 06 c6 45 fc 01 eb 47}  //weight: 2, accuracy: Low
        $x_1_4 = {4d 43 49 5f 44 50 49 33 32 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 52 56 5f 56 45 52 00}  //weight: 1, accuracy: High
        $x_1_6 = {67 62 5f 69 64 25 64 3d 00}  //weight: 1, accuracy: High
        $x_1_7 = {67 62 5f 64 61 74 61 00}  //weight: 1, accuracy: High
        $x_1_8 = {70 72 61 6d 3d 25 73 26 70 72 6f 74 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {25 73 3a 2a 3a 45 6e 61 62 6c 65 64 3a 69 70 73 65 63 00}  //weight: 1, accuracy: High
        $x_1_10 = {4f 4b 5f 41 64 64 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Pramro_B_2147607410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pramro.B"
        threat_id = "2147607410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pramro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 f9 81 c2 9b 04 00 00 89 95 ?? ?? ff ff 66 8b 95 ?? ?? ff ff 52 ff 15 06 00 99 b9 (10 27|40 1f) 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {c7 85 d4 ef ff ff f4 01 00 00 0f be ?? d1 df ff ff 83 ?? 02 89 ?? d0 ef ff ff eb 05 e9}  //weight: 2, accuracy: Low
        $x_1_3 = "NETSD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

