rule PWS_Win32_QQGame_D_2147601293_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQGame.D"
        threat_id = "2147601293"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQGame"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d8 6a f4 53 e8 ?? ?? ff ff 3d 88 42 00 00 75 26 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 56 e8}  //weight: 5, accuracy: Low
        $x_1_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQGame_F_2147614107_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQGame.F"
        threat_id = "2147614107"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQGame"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 c7 06 d8 07 ff 15 ?? ?? ?? ?? 66 83 7e 02 ?? 72 07 66 83 7e 06 ?? 73 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e3 01 00 00 68 3c 02 00 00 68 c8 00 00 00 8b f1 68 2c 01 00 00 e8 ?? ?? ?? ?? 8b 46 20 6a ec}  //weight: 1, accuracy: Low
        $x_1_3 = {bb 01 00 00 00 81 c2 42 ff ff ff 53 68 9f 00 00 00 68 00 01 00 00 05 fe fe ff ff 52 50 8b cd e8}  //weight: 1, accuracy: High
        $x_3_4 = {6a 04 52 68 4b e1 22 00 50 ff 15 ?? ?? ?? ?? 85 c0 74 10 ff 15 ?? ?? ?? ?? 85 c0 75 06}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

