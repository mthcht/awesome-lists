rule Trojan_Win64_Petwosel_A_2147941672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Petwosel.A"
        threat_id = "2147941672"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Petwosel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 10, accuracy: High
        $x_1_2 = {4d 5a 45 52 e8 00 00 00 00 59 48 83 e9 09 48 8b c1 48 05 ?? ?? ?? ?? ff d0 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 5a 45 52 e8 00 00 00 00 5b 48 83 eb 09 53 48 81 c3 ?? ?? ?? ?? ff d0 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 5a 45 52 e8 00 00 00 00 58 83 e8 09 50 05 ?? ?? ?? ?? ff d0 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Petwosel_B_2147941674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Petwosel.B"
        threat_id = "2147941674"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Petwosel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "132"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 100, accuracy: High
        $x_10_2 = {b8 4d 5a 00 00 [0-26] 81 3f 50 45 00 00}  //weight: 10, accuracy: Low
        $x_10_3 = {3c 02 0f 84 ?? 00 00 00 3c 03 75 ?? b8 00 20 00 00 66 85 ?? 16 0f 84 ?? 00 00 00}  //weight: 10, accuracy: Low
        $x_10_4 = {41 ff 16 48 8b e8 48 85 c0 74 62 8b 7b 10 48 03 fe eb 26 79 05 0f b7 d1 eb 07 48 8d 56 02 48 03 d1 48 85 d2 74 47 48 8b cd 41 ff 56 08}  //weight: 10, accuracy: High
        $x_1_5 = {b9 02 9f e6 6a}  //weight: 1, accuracy: High
        $x_1_6 = {ba 8d bd c1 3f}  //weight: 1, accuracy: High
        $x_1_7 = {ba ff 1f 7c c9}  //weight: 1, accuracy: High
        $x_1_8 = {41 81 f0 20 83 b8 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

