rule Trojan_Win32_Ledap_A_2147651330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ledap.A"
        threat_id = "2147651330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ledap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4c 24 1c 31 4e 08 8b 54 24 20 31 1e 31 6e 04 31 56 0c 83 c4 04 83 c6 10 83 ef 01 8d 4c 24 20 75 9f}  //weight: 2, accuracy: High
        $x_1_2 = {b9 c0 3b 9f 0a 0f c9 ba f9 1e 36 7d 0f ca 89 08 89 50 04}  //weight: 1, accuracy: High
        $x_1_3 = {47 68 6f 73 74 2e 64 6c 6c 00 50 6c 75 67 69 6e 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 61 66 61 72 69 2e 65 78 65 00 00 57 65 62 4b 69 74 32 57 65 62 50 72 6f 63 65 73 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 4f 46 54 57 41 52 45 5c 4d 61 63 72 6f 6d 65 64 69 61 00 43 6f 6e 66 69 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 40 25 00 25 7c 25 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ledap_A_2147655008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ledap.gen!A"
        threat_id = "2147655008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ledap"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6c 75 67 69 6e 4d 61 69 6e 00 50 6c 75 67 69 6e 4e 61 6d 65 00 50 6c 75 67 69 6e 54 79 70 65}  //weight: 1, accuracy: High
        $x_1_2 = {46 00 49 00 4c 00 03 00 46 00 49 00 4e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 50 c7 40 1c ?? ?? ?? ?? 8b 45 50 c7 40 5c ?? ?? ?? ?? eb 0c bb 7a 27 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {50 8b 06 50 8d 46 04 50 53 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

