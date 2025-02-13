rule Trojan_Win32_Foidan_A_2147670418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foidan.A"
        threat_id = "2147670418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foidan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 4f 00 49 00 44 00 43 00 54 00 52 00 4c 00 25 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {46 00 4f 00 43 00 54 00 52 00 4c 00 4d 00 00 00}  //weight: 1, accuracy: High
        $x_3_3 = {8a 00 3c eb 74 19 3c e9 74 15 3c e8 74 11 3c 68 74 0d 68 88 13 00 00 ff 15 ?? ?? ?? ?? eb dc}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Foidan_B_2147683223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foidan.B"
        threat_id = "2147683223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foidan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SYS_A7F20C8D" wide //weight: 1
        $x_1_2 = "SYS_B82C5620" wide //weight: 1
        $x_2_3 = {25 49 45 46 55 25 00}  //weight: 2, accuracy: High
        $x_2_4 = {58 2d 46 72 61 6d 65 2d 4f 70 74 69 6f 6e 73 00 53 41 4d 45 4f 52 49 47 49 4e}  //weight: 2, accuracy: High
        $x_3_5 = {8b 40 08 8a 00 3c eb 74 ?? 3c e9 74 ?? 3c e8 74 ?? 33 c9 3c 68 0f 94 c1 8b c1}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

