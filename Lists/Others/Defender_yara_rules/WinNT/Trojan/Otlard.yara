rule Trojan_WinNT_Otlard_A_2147622037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Otlard.A"
        threat_id = "2147622037"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 76 59 fe c5 0f 32 66 25 01 f0 48 66 81 38 4d 5a}  //weight: 2, accuracy: High
        $x_2_2 = {c6 45 fb 3d c6 45 fc 00 c7 45 c8 31 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {68 87 7e 34 c5 e8}  //weight: 1, accuracy: High
        $x_1_4 = {66 8b 11 81 fa ff 25 00 00 75 17 8b 45 f8 8b 48 02}  //weight: 1, accuracy: High
        $x_1_5 = {81 7d 08 ad de 01 c0 75 0a b8 ad de 01 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Otlard_B_2147624214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Otlard.B"
        threat_id = "2147624214"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d 08 ad de 01 c0 75 0a b8 ad de 01 c0}  //weight: 1, accuracy: High
        $x_1_2 = {68 ce c5 18 a7 e8 ?? ?? ?? ?? 40 8b 18 80 fb e8}  //weight: 1, accuracy: Low
        $x_1_3 = {be 85 00 00 00 f7 fe 6b d2 03 03 ca 81 e1 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 10 e8 04 00 00 00 0f 01 0c 24 5e a5 b8 04 00 00 00 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_WinNT_Otlard_C_2147626503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Otlard.C"
        threat_id = "2147626503"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hGoot" ascii //weight: 1
        $x_1_2 = {8b 4d f8 0f b6 11 83 fa 55 75 ec}  //weight: 1, accuracy: High
        $x_1_3 = {be 85 00 00 00 f7 fe 6b d2 03 03 ca 81 e1 ff 00 00 00 88 8d}  //weight: 1, accuracy: High
        $x_1_4 = {b8 22 00 00 c0 eb 3a 83 7d fc 00 75 04 33 c0 eb 30 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_WinNT_Otlard_D_2147631225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Otlard.D"
        threat_id = "2147631225"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 6f 6f 74 6b 69 74 00}  //weight: 1, accuracy: High
        $x_2_2 = {8b 08 c1 e9 05 83 e1 07 83 c1 01 83 e1 07 c1 e1 05}  //weight: 2, accuracy: High
        $x_1_3 = {68 26 c4 31 50 e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 50 68 7f 92 2b 7d e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Otlard_F_2147631471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Otlard.F"
        threat_id = "2147631471"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 fc 03 95 00 ff ff ff 81 7a fc 37 13 d3 a0 74}  //weight: 2, accuracy: High
        $x_1_2 = {b8 22 00 00 c0 eb 38 83 7d fc 00 75 04 33 c0 eb 2e 68}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 e8 83 c6 45 e9 ec c6 45 ea 04 c6 45 eb c7 c6 45 ec 04 c6 45 ed 24}  //weight: 1, accuracy: High
        $x_1_4 = "Gootkit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Otlard_G_2147632719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Otlard.G"
        threat_id = "2147632719"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 48 38 51 6a 00 ff 55 fc}  //weight: 1, accuracy: High
        $x_1_2 = {b8 2c f1 df ff 8b 00 66 25 01 f0 48 66 81 38 4d 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Otlard_H_2147647624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Otlard.H"
        threat_id = "2147647624"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 32 66 25 01 f0 48 66 81 38 4d 5a 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {c1 c2 03 32 10 40 80 38 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 2e 58 6a 73 66 89 45 f4 58 6a 79 66 89 45 f6 58 66 89 45 f8 6a 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

