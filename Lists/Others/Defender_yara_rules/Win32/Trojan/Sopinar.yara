rule Trojan_Win32_Sopinar_A_2147693202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sopinar.A"
        threat_id = "2147693202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sopinar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 3d 03 00 00 00 33 c0 c6 05 11 00 00 00 04 40 c7 05 5b 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = {83 04 24 02 c7 45 ?? 60 9c e8 03 c7 45 ?? 00 00 00 9d}  //weight: 1, accuracy: Low
        $x_1_3 = {66 c7 45 fc eb f9 66 c7 45 f8 8b ff eb 0b}  //weight: 1, accuracy: High
        $x_10_4 = {2d 00 75 00 20 00 2d 00 71 00 20 00 2d 00 6e 00 20 00 22 00 25 00 73 00 22 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sopinar_B_2147693441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sopinar.B"
        threat_id = "2147693441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sopinar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3c 31 22 11 22 11 75 ?? c7 04 31}  //weight: 1, accuracy: Low
        $x_1_2 = "{861e4d8a-168b-4b90-a04f-34f72ee701e0}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sopinar_C_2147705923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sopinar.C"
        threat_id = "2147705923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sopinar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 f3 aa c7 06 63 68 72 6f c7 46 04 6d 65 2e 65 66 c7 46 08 78 65 e8 03 00 b9 0b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {76 65 6e 64 c7 44 24 ?? 6f 72 5f 69 c7 44 24 ?? 64 00 00 00 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_3 = {68 9c f1 01 5d 8b 55 fc 8b 42 04 50 8b 4d fc 8b 11 52 e8 ?? ?? ?? ?? 8b 4d fc 89 41 2c 68 d3 bb 7e 87}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 0c 06 8d 40 01 80 f1 41 88 48 ff 4a 75 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sopinar_D_2147707584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sopinar.D"
        threat_id = "2147707584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sopinar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0e 8d 49 01 34 ?? 88 41 ff 4a 75 f2}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 06 25 73 5c 25 66 c7 46 04 73 5c}  //weight: 1, accuracy: High
        $x_1_3 = {c7 06 73 6e 78 68 c7 46 04 6b 2e 64 6c c6 46 08 6c}  //weight: 1, accuracy: High
        $x_1_4 = {8a 0c 06 8d 40 01 80 f1 ?? 88 48 ff 4a 75 f1}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 02 63 68 72 6f c7 42 04 6d 65 2e 65 66 c7 42 08 78 65}  //weight: 1, accuracy: High
        $x_1_6 = {c7 02 73 61 66 61 c7 42 04 72 69 2e 65 66 c7 42 08 78 65}  //weight: 1, accuracy: High
        $x_1_7 = {c7 02 6f 70 65 72 c7 42 04 61 2e 65 78 c6 42 08 65}  //weight: 1, accuracy: High
        $x_1_8 = {c7 02 6d 73 6d 73 c7 42 04 67 73 2e 65 66 c7 42 08 78 65}  //weight: 1, accuracy: High
        $x_1_9 = {c7 06 6a 76 79 73 c7 46 04 63 6a 74 61 66 c7 46 08 76 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Sopinar_F_2147718416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sopinar.F!bit"
        threat_id = "2147718416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sopinar"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 31 33 f0 81 e6 ff 00 00 00 c1 e8 08 33 04 b5 ?? ?? ?? ?? 41 4a 75 e7}  //weight: 2, accuracy: Low
        $x_1_2 = {64 a1 30 00 00 00 8b 48 0c 8b 41 0c}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 08 33 ca [0-32] 88 0a eb}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 e8 72 00 6e 00 c7 45 ec 65 00 6c 00 c7 45 f0 33 00 32 00 c7 45 f4 2e 00 64 00 c7 45 f8 6c 00 6c 00 66 89 4d fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

