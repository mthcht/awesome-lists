rule Trojan_Win32_Loshi_A_2147667443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Loshi.A"
        threat_id = "2147667443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Loshi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 55 02 45 89 54 24 14 8b 44 24 10 45 3b e8 7c 81 53 e8}  //weight: 2, accuracy: High
        $x_2_2 = {7e 7f 80 3c 2b 0d 75 70 80 7c 2b 01 0a 75 69 8b 54 24 14 8b c5 2b c2 bf}  //weight: 2, accuracy: High
        $x_2_3 = {8a 14 01 32 db 80 fa 41 7c 0d 80 fa 5a 7f 08 80 c2 20 b3 01 88 14 01 0f be 14 01 8d 72 df 83 fe 5c}  //weight: 2, accuracy: High
        $x_2_4 = {7e 15 b0 5c 38 44 0c 34 74 08 49 83 f9 09 7f f4 eb 05 c6}  //weight: 2, accuracy: High
        $x_1_5 = {22 25 73 5c 72 65 67 74 6d 70 31 22 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 5c 72 65 67 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {25 45 43 25 38 32 25 41 44 25 45 43 25 41 30 25 39 43 00}  //weight: 1, accuracy: High
        $x_1_8 = "%s\\fstfg.ini" wide //weight: 1
        $x_1_9 = {4d 66 66 78 67 78 6f 6d 6b 72 6f 00}  //weight: 1, accuracy: High
        $x_1_10 = {6c 61 6f 73 68 69 31 33 35 2e 7a 68 61 6e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

