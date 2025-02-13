rule Backdoor_WinNT_Rustock_F_2147792048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Rustock.F"
        threat_id = "2147792048"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Rustock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c3 04 83 c0 f8 c1 e8 02 8b cb 74 08 31 11 83 c1 04 48 75 f8}  //weight: 10, accuracy: High
        $x_10_2 = {55 8b ec 56 8b 75 1c 85 f6 74 37 83 7e 04 00 74 31 e8 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 74 24 ff 35 ?? ?? ?? ?? ff 76 04 ff 15 ?? ?? ?? ?? 59 50 ff 15 ?? ?? ?? ?? 85 c0 59 59 74 07 b8 01 00 00 c0 eb 26}  //weight: 10, accuracy: Low
        $x_9_3 = {81 3e 52 43 50 54 0f 85 ?? ?? ?? ?? 81 7e 04 20 54 4f 3a}  //weight: 9, accuracy: Low
        $x_1_4 = {83 23 00 c7 45 10 34 00 00 c0}  //weight: 1, accuracy: High
        $x_1_5 = "C8453B23-1087-27d9-1394-CDBF03EC72D8" wide //weight: 1
        $x_1_6 = "60F9FCD0-8DD4-6453-E394-771298D2A47" wide //weight: 1
        $x_1_7 = "5B37FB3B-984D-1E57-FF38-AA681BE5C8D" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_9_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_WinNT_Rustock_A_2147792392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Rustock.gen!A"
        threat_id = "2147792392"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Rustock"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 38 50 e8 ?? ?? ff ff 8b 45 fc 68 ?? ?? ?? ?? 83 c0 68 50 e8 ?? ?? ff ff 8b 75 fc 68 e0 90 b6 1c}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 06 58 c6 46 01 68 89 76 02 c6 46 06 50 c6 46 07 68 c6 46 0c c3}  //weight: 1, accuracy: High
        $x_1_3 = {68 b7 a4 7b 0f 6a 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_WinNT_Rustock_D_2147792411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Rustock.gen!D"
        threat_id = "2147792411"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Rustock"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 7b 80 7f 09 32 0f 85 ?? ?? ?? ?? 80 7f 0a 30 0f 85 ?? ?? ?? ?? 80 7f 0b 30}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f3 03 34 8f 33 c0 c1 c0 07 32 06 46 80 3e 00 75 f5 35 ad 6d bf e8 74 0a 41 3b 4a 18 75 e1}  //weight: 1, accuracy: High
        $x_1_3 = {3d de c0 ad de 75 0d 83 65 ?? 00 eb 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_WinNT_Rustock_J_2147792434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Rustock.J"
        threat_id = "2147792434"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Rustock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 01 00 00 00 0f a2 81 e2 00 08 00 00 85 d2 74 ?? b9 74 01 00 00 0f 32 89 45 ?? b9 75 01 00 00 0f 32 89 45 ?? b9 76 01 00 00 0f 32 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 41 60 56 8b 72 08 fe 49 23 83 e8 24 89 41 60 89 50 14 0f b6 00 51 52 ff 54 86 38 5e c3}  //weight: 1, accuracy: High
        $x_1_3 = {8d 88 00 10 00 00 eb ?? 2b c8 eb ?? 66 81 38 8d 88 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_WinNT_Rustock_C_2147792435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Rustock.gen!C"
        threat_id = "2147792435"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Rustock"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 24 6a 03 36 ff 75 08}  //weight: 2, accuracy: High
        $x_1_2 = {66 81 38 4d 5a}  //weight: 1, accuracy: High
        $x_2_3 = {8b 45 ec 03 40 3c 8b 48 50}  //weight: 2, accuracy: High
        $x_1_4 = {0f b7 f8 66 81 e7 ff 0f 66 c1 e8 0c 83 f8 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_WinNT_Rustock_E_2147792436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Rustock.gen!E"
        threat_id = "2147792436"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Rustock"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 00 6d 00 61 00 67 00 65 00 50 00 61 00 74 00 68 00 00 00 5c 00 3f 00 3f 00 5c 00 25 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 44 00 52 00 49 00 56 00 45 00 52 00 53 00 5c 00 25 00 77 00 73 00 25 00 63 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff 75 f4 ff 15 ?? ?? 01 00 ff 75 f4 ff 15 ?? ?? 01 00 8d 85 88 f6 ff ff 50 8d 45 e0 50 ff d6 8d 45 e0 50 e8 ?? ?? ?? ?? 5f 5e b8 83 01 00 c0 5b c9 c2 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

