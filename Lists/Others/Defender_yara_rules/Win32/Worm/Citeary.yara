rule Worm_Win32_Citeary_B_2147627642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Citeary.B"
        threat_id = "2147627642"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Citeary"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 6f 64 75 6c 65 41 6e 74 69 2e 64 6c 6c 00 45 78 70 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 6f 64 75 65 44 6f 77 6e 2e 64 6c 6c 00 45 78 70 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {7d 16 8b 55 08 03 55 fc 0f be 02 33 45 14 8b 4d 0c 03 4d fc 88 01 eb d9}  //weight: 1, accuracy: High
        $x_1_4 = {ff d1 c6 85 ?? ?? ?? ?? 5c c6 85 ?? ?? ?? ?? 5c c6 85 ?? ?? ?? ?? 2e c6 85 ?? ?? ?? ?? 5c c6 85 ?? ?? ?? ?? 49 c6 85 ?? ?? ?? ?? 63 c6 85 ?? ?? ?? ?? 79 c6 85 ?? ?? ?? ?? 48}  //weight: 1, accuracy: Low
        $x_1_5 = {ff d2 c6 45 ?? 73 c6 45 ?? 61 c6 45 ?? 66 c6 45 ?? 65 c6 45 ?? 6d c6 45 ?? 6f c6 45 ?? 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {ff 70 c6 85 ?? ?? ff ff 20 c6 85 ?? ?? ff ff 77 c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 76 c6 85 ?? ?? ff ff 63}  //weight: 1, accuracy: Low
        $x_1_7 = {c6 45 db 43 eb 08 8a 45 db 04 01 88 45 db 0f be 4d db 83 f9 5a 0f 8f}  //weight: 1, accuracy: High
        $x_1_8 = {ff 5b c6 85 ?? ?? ff ff 41 c6 85 ?? ?? ff ff 75 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 52 c6 85 ?? ?? ff ff 75 c6 85 ?? ?? ff ff 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Citeary_C_2147631467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Citeary.C"
        threat_id = "2147631467"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Citeary"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 73 c6 85 ?? ?? ?? ?? 79 c6 85 ?? ?? ?? ?? 73 c6 85 ?? ?? ?? ?? 74 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 6d c6 85 ?? ?? ?? ?? 2e c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 78 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_2 = {ff 73 c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 74 c6 85 ?? ?? ?? ?? 20 c6 85 ?? ?? ?? ?? 79 c6 85 ?? ?? ?? ?? 75 c6 85 ?? ?? ?? ?? 3d}  //weight: 2, accuracy: Low
        $x_1_3 = {68 00 ba db 00 ff 15 ?? ?? ?? ?? eb e5}  //weight: 1, accuracy: Low
        $x_2_4 = {44 6f 77 6e 4d 6f 64 75 6c 65 2e 64 6c 6c 00 45 78 65 63 75 74 65 00}  //weight: 2, accuracy: High
        $x_1_5 = {5c 73 79 73 74 65 6d 2e 64 61 74 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Citeary_E_2147643776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Citeary.E"
        threat_id = "2147643776"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Citeary"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 41 7c 21 8b 4d 08 0f be 11 83 fa 5a 7f 16 8b 45 f4 0f af 45 fc 8b 4d 08 0f be 11 8d 44 10 20}  //weight: 1, accuracy: High
        $x_1_2 = {68 09 20 22 00 8b 55 ?? ?? ff 15 ?? ?? ?? ?? 68 b8 0b 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

