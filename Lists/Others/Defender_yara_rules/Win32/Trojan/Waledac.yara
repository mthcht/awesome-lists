rule Trojan_Win32_Waledac_A_137938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waledac.gen!A"
        threat_id = "137938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waledac"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 45 98 33 db 50 89 5d fc e8 ?? ?? 00 00 c6 45 fc 01 8b 4d c8 8d 7d 98 e8 ?? ?? ff ff 39 1e 74 15 6a 03}  //weight: 4, accuracy: Low
        $x_4_2 = {8d 45 98 33 db 50 89 5d fc e8 ?? ?? 00 00 c6 45 fc 01 8b 4d c8 6a 01 8d 7d 98 e8 ?? ?? ff ff 39 1e 59 74 18 6a 03}  //weight: 4, accuracy: Low
        $x_4_3 = {3b f7 76 11 8b 45 e8 8d 04 88 81 30 ?? ?? ?? ?? 41 3b ce 72 ef 8b 75 d8 57}  //weight: 4, accuracy: Low
        $x_2_4 = {c6 00 2d 8b 46 0c 8b 40 04 57 6a 2b 50 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 75 e7 eb 03 c6 00 5f}  //weight: 2, accuracy: Low
        $x_2_5 = {2f 6c 6d 2f 6d 61 69 6e 2e 70 68 70 00}  //weight: 2, accuracy: High
        $x_1_6 = {77 6f 72 64 73 00 00 00 74 61 73 6b}  //weight: 1, accuracy: High
        $x_1_7 = {52 4c 69 73 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {4c 61 73 74 43 6f 6d 6d 61 6e 64 49 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {50 72 6f 6d 6f 52 65 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Waledac_B_137942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waledac.gen!B"
        threat_id = "137942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waledac"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 01 00 00 80 79 05 48 83 c8 fe 40 74 07 68 ?? ?? ?? ?? eb 05 68 ?? ?? ?? ?? 57 e8 ?? ?? ?? ff 8b c7}  //weight: 2, accuracy: Low
        $x_2_2 = {75 76 77 78 79 7a 00 00 2e 70 6e 67 00 00 00 00 2e 68 74 6d 00 00 00 00 46 57 44 6f 6e 65 00}  //weight: 2, accuracy: High
        $x_1_3 = {77 6f 72 64 73 00 00 00 74 61 73 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 4c 69 73 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {4c 61 73 74 43 6f 6d 6d 61 6e 64 49 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 72 6f 6d 6f 52 65 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

