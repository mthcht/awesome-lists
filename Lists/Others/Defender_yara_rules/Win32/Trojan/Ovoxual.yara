rule Trojan_Win32_Ovoxual_A_2147630357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ovoxual.A"
        threat_id = "2147630357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ovoxual"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 10 6f c6 44 24 15 78}  //weight: 1, accuracy: High
        $x_1_2 = {88 4c 24 14 88 5c 24 17 c6 44 24 0e 63}  //weight: 1, accuracy: High
        $x_1_3 = {b2 65 b0 6e b1 74}  //weight: 1, accuracy: High
        $x_1_4 = {8d 7c 24 20 f3 a5 66 81 7c 24 20 4d 5a}  //weight: 1, accuracy: High
        $x_1_5 = {8d 54 24 10 51 8b 4c 24 3c 6a 04 83 c0 08}  //weight: 1, accuracy: High
        $x_1_6 = {8b 4c 24 48 3b c1 c7 44 24 54 07 00 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Ovoxual_B_2147653577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ovoxual.B"
        threat_id = "2147653577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ovoxual"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 85 df fe ff ff 45 c6 85 e0 fe ff ff 53 c6 85 e1 fe ff ff 2e c6 85 e2 fe ff ff 44 c6 85 d8 fe ff ff 46 c6 85 d9 fe ff ff 41 c6 85 da fe ff ff 56 c6 85 de fe ff ff 54 c6 85 e3 fe ff ff 41 c6 85 e4 fe ff ff 54 80 a5 e5 fe ff ff 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 eb 56 c6 45 ec 69 c6 45 ed 65 c6 45 ee 77 c6 45 ef 4f c6 45 f0 66 c6 45 f1 53 c6 45 f2 65 c6 45 f3 63 c6 45 f4 74 c6 45 f5 69 c6 45 f6 6f c6 45 f7 6e c6 45 d8 6e c6 45 d9 74 c6 45 da 64 c6 45 db 6c c6 45 dc 6c c6 45 dd 2e c6 45 de 64 c6 45 df 6c c6 45 e0 6c ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 eb 56 c6 45 ec 69 c6 45 f3 63 c6 45 f4 74 c6 45 f5 69 c6 45 f6 6f c6 45 f7 6e c6 45 d8 6e c6 45 d9 74 c6 45 da 64 c6 45 db 6c c6 45 dc 6c c6 45 dd 2e c6 45 de 64 c6 45 df 6c c6 45 e0 6c ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 f1 76 c6 45 f8 65 c6 45 f5 73 88 5d fb c6 45 f2 63 c6 45 f0 73 c6 45 f6 74 c6 45 f7 2e c6 45 f3 68 c6 45 fa 65 ff 15}  //weight: 1, accuracy: High
        $x_1_5 = {8b 7d 0c 57 c7 07 07 00 01 00 ff 76 04 ff 15 ?? ?? ?? ?? 8b 5d 10 8d 45 08 50 8b 87 a4 00 00 00 6a 04 83 c0 08 53 50 ff 36 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

