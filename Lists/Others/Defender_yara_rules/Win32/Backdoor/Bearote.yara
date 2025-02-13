rule Backdoor_Win32_Bearote_A_2147614204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bearote.A"
        threat_id = "2147614204"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bearote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 1d 6a 05 53 e8 ?? ?? ff ff 8b f8 89 fe 85 ff 74 0d 6a ff 8d 85 ?? ?? ff ff 50 6a 00 ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c0 74 11 68 ?? ?? ?? ?? 6a 00 6a 00 50 e8 ?? ?? ?? ?? 8b d8 85 db 74 0f 6a 00 6a 00 68 f5 00 00 00 53 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {83 fe 05 75 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 fe 06 75 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Bearote_B_2147620119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bearote.B"
        threat_id = "2147620119"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bearote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 06 00 00 00 ba 01 00 00 00 b8 02 00 00 00 e8 ?? ?? ff ff 89 45 f4 83 7d f4 ff 74 10 84 db 75 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {74 19 3d 4c 27 00 00 74 12 3d 33 27 00 00 74 0b 3d 36 27 00 00 74 04}  //weight: 1, accuracy: High
        $x_1_3 = {2e 64 6c 6c 00 49 6e 73 74 61 6c 6c [0-8] 53 65 72 76 69 63 65 4d 61 69 6e 00 55 6e 73 74 61 6c 6c}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 68 74 6d 6c 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 69 6e 58 70 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_6 = "\\DelEx.bat" ascii //weight: 1
        $x_1_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 [0-16] 2e 75 6e 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

