rule Trojan_Win32_Lecpetex_C_2147687792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lecpetex.C"
        threat_id = "2147687792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lecpetex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 72 c3 0d 76 77 47 4e 3c 22 d6 cc 95 58 e3 9e d2 50 1a a7}  //weight: 2, accuracy: High
        $x_1_2 = {6a 00 6a 04 8d 55 fc 52 68 18 74 41 00 8b 85 08 fd ff ff 50 ff 15}  //weight: 1, accuracy: High
        $x_2_3 = {0b eb ac 00 63 1f 80 94 e1 55 ce 54 3f a3 65 3c ad 85 b8 c4 1f 58 2e ac 13 f6 02 1b f4 04 59 0c}  //weight: 2, accuracy: High
        $x_2_4 = {54 92 53 61 18 8c fd f2 97 a0 23 79 47 ed 73 b7 74 e7 c1 c3 02 ca a5 c4 fe 1a 56 97 2b a0 89 bf}  //weight: 2, accuracy: High
        $x_1_5 = {70 65 70 65 65 65 00 00 73 74 66 75 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 65 70 65 00 00 00 00 6b 65 79 00 6c 65 50 65 77}  //weight: 1, accuracy: High
        $x_1_7 = {c6 45 d0 8f c6 45 d1 98 c6 45 d2 5c c6 45 d3 62 c6 45 d4 c5 c6 45 d5 b7 c6 45 d6 f0 c6 45 d7 4d c6 45 d8 c1 c6 45 d9 7a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

