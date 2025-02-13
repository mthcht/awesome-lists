rule TrojanDropper_Win32_OnLineGames_H_2147619318_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/OnLineGames.H"
        threat_id = "2147619318"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 f9 8a 82 ?? ?? ?? ?? 8a 54 1f ff 32 c2 5a 88 02 43 4e 75 d7}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 00 6a 00 68 f5 00 00 00 ?? e8 ?? ?? ff ff 83 f8 01}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 65 74 20 73 74 6f 70 20 53 79 73 74 65 6d 20 52 65 73 74 6f 72 65 20 53 65 72 76 69 63 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {6e 65 74 20 73 74 6f 70 20 22 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_OnLineGames_E_2147646778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/OnLineGames.E"
        threat_id = "2147646778"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "OnLineGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 6f 68 7a 57 65 74 69 62 62 51 6d 63 74 6f 73 6f 68 7a 62 62 57 6d 70 6a 6f 77 73 62 62 43 79 74 74 69 70 7a 58 69 74 73 6d 6f 70 62 62 54 79 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {58 33 52 43 7a 74 72 5f 53 7a 6f 76 53 69 74 78 6d 63 69 5f 4d 70 73 7a 00}  //weight: 1, accuracy: High
        $x_1_3 = {58 33 52 43 7a 74 72 5f 59 70 54 69 67 6d 73 7a 69 74 53 69 74 78 6d 63 69 56 72 79 67 4d 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {c6 06 4d c6 46 01 5a}  //weight: 1, accuracy: High
        $x_1_5 = {b9 fe 00 00 00 56 f7 f9 8b 74 24 0c fe c2 85 f6 76 10 8b 44 24 08 8a 08 2a ca 32 ca 88 08 40 4e 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

