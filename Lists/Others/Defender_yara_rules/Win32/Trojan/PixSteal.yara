rule Trojan_Win32_PixSteal_A_2147667405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PixSteal.A"
        threat_id = "2147667405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PixSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b8 cc cc cc cc f3 ab 8b f4 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b f4 6a 00 68 ?? ?? ?? ?? ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {83 c4 08 8b f4 68 e8 03 00 00 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b f4 6a 00 6a 00 6a 00 6a 01 6a 00 ff 15 ?? ?? ?? ?? 3b f4 e8}  //weight: 5, accuracy: Low
        $x_2_3 = {43 6f 6e 73 6f 6c 65 57 69 6e 64 6f 77 43 6c 61 73 73 00}  //weight: 2, accuracy: High
        $x_2_4 = {43 3a 5c 00 43 3a 5c 2a 2e 2a 00}  //weight: 2, accuracy: High
        $x_1_5 = {29 20 64 6f 20 40 63 6f 70 79 20 2f 79 20 25 78 20 43 3a 5c 00}  //weight: 1, accuracy: High
        $x_1_6 = {77 61 73 69 74 6e 65 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

