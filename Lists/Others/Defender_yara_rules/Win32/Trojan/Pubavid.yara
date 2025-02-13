rule Trojan_Win32_Pubavid_A_2147634183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pubavid.A"
        threat_id = "2147634183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pubavid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {42 6c 61 63 6b 73 42 6c 65 65 64 00 76 69 72 74 75 61 6c 20 70 63 00 00 58 58 58 42 41 2e 52 45 53 55 52 00}  //weight: 5, accuracy: High
        $x_5_2 = {42 6c 61 63 6b 73 42 6c 65 65 64 00 76 69 72 74 75 61 6c 20 70 63 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00}  //weight: 5, accuracy: High
        $x_5_3 = {53 62 69 65 44 6c 6c 2e 64 6c 6c 00 76 69 72 74 75 61 6c 20 70 63 00 00 54 45 4d 50 00}  //weight: 5, accuracy: High
        $x_1_4 = {42 41 56 31 44 4c 4c 2e 64 6c 6c 00 44 72 61 77 54 65 78 74 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {42 41 56 31 44 4c 4c 2e 64 6c 6c 00 53 75 63 6b 73 00}  //weight: 1, accuracy: High
        $x_10_6 = {55 8b ec 56 33 f6 39 75 10 7c 1a 8b 45 08 8d 0c 06 8b c6 99 f7 7d 14 8b 45 0c 8a 04 02 30 01 46 3b 75 10 7e e6 5e 5d c3}  //weight: 10, accuracy: High
        $x_10_7 = {8b f1 99 f7 fe 8b 75 f8 8a 84 95 ?? ?? ff ff 30 06 ff 45 14 8b 45 14 3b 45 10 72 95 8b 45 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Pubavid_B_2147637334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pubavid.B"
        threat_id = "2147637334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pubavid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 00 e9 ff 06 8b 06 2b d8 8d 4c 3b fc 89 08 83 c8 ff 2b c7 5f 01 06}  //weight: 1, accuracy: High
        $x_1_2 = {8a 04 02 30 01 46 3b (74|75) [0-3] 7e}  //weight: 1, accuracy: Low
        $x_1_3 = {42 41 56 31 44 4c 4c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

