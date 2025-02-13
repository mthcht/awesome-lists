rule Trojan_Win32_Chroject_B_2147689398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chroject.B"
        threat_id = "2147689398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chroject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 46 14 02 89 7e 08 8b 46 10 03 46 08 88 18 ff 46 10 8b 4e 10 8b 46 14 3b c8}  //weight: 2, accuracy: High
        $x_2_2 = {8b 04 01 3d 6c 6f 77 69 75}  //weight: 2, accuracy: High
        $x_2_3 = {ff d6 33 d2 b9 0a 00 00 00 f7 f1 83 c2 14 69 d2 b8 0b 00 00 52 ff d7 ff d6 2b c3}  //weight: 2, accuracy: High
        $x_1_4 = {78 65 6e 76 64 62 00}  //weight: 1, accuracy: High
        $x_1_5 = {76 6d 69 63 65 78 63 68 61 6e 67 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chroject_D_2147689957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chroject.D!dll"
        threat_id = "2147689957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chroject"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 40 08 8b 4d 08 6a 00 6a 00 50 51 6a 00 e8 ?? ?? ?? ?? 8b 55 00 85 c0 8b 42 08 8b cd 7d 1b ff d0}  //weight: 2, accuracy: Low
        $x_2_2 = {2a 2a 6a 73 75 11 81 bc 24 ?? ?? 00 00 6d 73 67 7c}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 06 8b 50 04 8b ce ff d2 8b 44 24 10 53 8a 18 80 f3}  //weight: 2, accuracy: High
        $x_1_4 = {8b 55 08 8a 14 16 90 38 14 19 74 14}  //weight: 1, accuracy: High
        $x_1_5 = {83 7e 10 04 76 0e 8b 46 08 80 78 04 3a 75 05 bf 07 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {83 ff 04 76 0e 8b 4e 08 80 79 04 3a 75 05 b8 07 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {43 68 61 72 67 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Chroject_E_2147690031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chroject.E!dll"
        threat_id = "2147690031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chroject"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 68 61 72 67 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {47 6f 6c 64 65 6e 41 78 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 5c 52 e8 ?? ?? ?? ?? 8b f8 83 c4 08 83 c7 01}  //weight: 1, accuracy: Low
        $x_1_4 = {45 8b c5 83 e0 03 8a 5c 04 10 32 1c 29}  //weight: 1, accuracy: High
        $x_1_5 = {89 7e 08 8b 46 10 03 46 08 88 18 ff 46 10 8b 4e 10 8b 46 14 3b c8 73 13}  //weight: 1, accuracy: High
        $x_2_6 = {8b 48 04 ff d1 8d 55 fc 52 8d 45 f4 50 6a 00 6a 00 8b 4d f0 8b 11 ff d2 8b 45 fc 50 8b 4d f0 8b 51 08 ff d2}  //weight: 2, accuracy: High
        $x_2_7 = {ff d3 85 c0 74 ?? 81 7c 24 14 80 00 00 00 75 ?? 6a 00 6a 00 55 57 6a 00 6a 00 56 c7 05 ?? ?? ?? ?? 0b 00 00 00 ff 15 ?? ?? ?? ?? 8b d8 ff 15 ?? ?? ?? ?? 85 db 74 ?? 68 88 13 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

