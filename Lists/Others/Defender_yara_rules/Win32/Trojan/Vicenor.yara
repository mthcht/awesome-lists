rule Trojan_Win32_Vicenor_A_171002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vicenor.gen!A"
        threat_id = "171002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vicenor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "darkSons_crypt" ascii //weight: 2
        $x_1_2 = {81 bd fc fb ff ff 10 27 00 00 75 07 6a 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 8d 4c fc ff ff 83 c1 08 6a 00 6a 04 8d 85 fc fe ff ff 50 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vicenor_B_171231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vicenor.gen!B"
        threat_id = "171231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vicenor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 20 2d 61 20 ?? ?? 20 2d 67 20 [0-3] 20 2d 6f 20 68 74 74 70 3a [0-64] 20 2d 75 20 [0-32] 20 2d 70 20}  //weight: 1, accuracy: Low
        $x_10_2 = {05 04 01 00 00 03 45 fc 03 45 08 50 6a 04 50 8d 85 ?? ?? ff ff 50 e8}  //weight: 10, accuracy: Low
        $x_10_3 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 ff 75 10 ff 75 0c e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c8 68 ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? ff b5 ?? ?? ff ff ff b5 ?? ?? ff ff ff d0 6a 40 68 00 30 00 00 ff b5 ?? ?? ff ff ff b5 ?? ?? ff ff ff b5 ?? ?? ff ff e8}  //weight: 10, accuracy: Low
        $x_1_4 = {2e 65 78 65 20 2d 61 20 ?? ?? 20 2d 6c 20 [0-3] 20 2d 6f 20 68 74 74 70 3a [0-64] 20 2d 75 20 [0-32] 20 2d 70 20}  //weight: 1, accuracy: Low
        $x_1_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 57 49 4e 53 58 53 33 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vicenor_E_198141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vicenor.E"
        threat_id = "198141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vicenor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff b5 ?? ?? ff ff e8 ?? ?? ?? ?? 89 85 ?? ?? ff ff 6a 00 ff 77 54 ff 75 ?? ff b5 ?? ?? ff ff ff b5 ?? ?? ff ff e8}  //weight: 2, accuracy: Low
        $x_1_2 = {31 00 44 00 46 00 41 00 47 00 58 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2d 00 6f 00 20 00 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

