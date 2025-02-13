rule Trojan_Win32_Avgesi_B_2147680239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Avgesi.B"
        threat_id = "2147680239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Avgesi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b8 f6 6f 04 00 d3 e8 f6 d0 30 (45|44 24)}  //weight: 3, accuracy: Low
        $x_1_2 = {bf 01 00 00 00 8b 45 ?? 03 06 05 05 33 db 8a 5c 38 ff 0f b6 5c 38 ff 0f b7 5c 78 fe 33 5d ?? 3b 5d ?? 7f 0b 81 c3 ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 4e 42 56 43 58 5a 4c 4b 4a 48 47 46 44 53 41 50 4f 49 55 59 54 52 45 57 51 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 00 4e 00 42 00 56 00 43 00 58 00 5a 00 4c 00 4b 00 4a 00 48 00 47 00 46 00 44 00 53 00 41 00 50 00 4f 00 49 00 55 00 59 00 54 00 52 00 45 00 57 00 51 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {32 46 44 30 33 31 46 41 32 45 44 35 00}  //weight: 1, accuracy: High
        $x_1_6 = {41 39 36 36 42 43 34 45 42 30 35 30 30 39 31 46 45 34 32 36 33 36 45 38 33 44 44 35 32 43 46 32 00}  //weight: 1, accuracy: High
        $x_2_7 = {8b 38 ff 57 ?? 8b ce 8b 45 ?? d3 e8 f6 d0 30 45 ?? 8d 55 ?? b9 01 00 00 00 8b 45 ?? 8b 38 ff 57 ?? 46 4b 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

