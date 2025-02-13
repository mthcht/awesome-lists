rule PWS_Win32_Bividon_A_2147600215_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Bividon.A"
        threat_id = "2147600215"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Bividon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 45 ec 6a 40 68 00 30 00 00 8d 45 e8 8b d6 e8 ?? ?? ?? ff 8b 45 e8 e8 ?? ?? ?? ff 40 50 6a 00 53 ff d7 8b f8 8d 45 f4 50 8d 45 e4 8b d6 e8 ?? ?? ?? ff 8b 45 e4 e8 ?? ?? ?? ff 40 50 56 57 53 ff 55 ec}  //weight: 3, accuracy: Low
        $x_1_2 = {66 81 3f 4d 5a 75 11 8d 46 3c 8b 18 03 de 81 3b 50 45 00 00 74 02}  //weight: 1, accuracy: High
        $x_1_3 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 00 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63}  //weight: 1, accuracy: High
        $x_1_4 = {56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 55 8b}  //weight: 1, accuracy: High
        $x_1_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 00 4c 6f 61 64 4c 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Bividon_A_2147600216_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Bividon.A"
        threat_id = "2147600216"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Bividon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 fc 8a 54 1a ff 80 f2 e9 88 54 18 ff 43 4e 75 e6}  //weight: 1, accuracy: High
        $x_1_2 = {bb 01 00 00 00 8d 45 ec 50 b9 01 00 00 00 8b d3 8b c7}  //weight: 1, accuracy: High
        $x_1_3 = {77 69 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {80 38 01 75 0c 68 00 ba db 00 e8}  //weight: 1, accuracy: High
        $x_1_5 = {2d 93 08 00 00 74 0c 2d 95 01 00 00 74 36}  //weight: 1, accuracy: High
        $x_3_6 = "SetWindowsHook" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Bividon_2147607383_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Bividon"
        threat_id = "2147607383"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Bividon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 fc 8a 54 1a ff 80 f2 e9 88 54 18 ff 43 4e 75 e6}  //weight: 10, accuracy: High
        $x_10_2 = {41 70 70 44 61 74 61 00 ff ff ff ff 40 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73}  //weight: 10, accuracy: High
        $x_1_3 = {6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40}  //weight: 1, accuracy: High
        $x_1_4 = {56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 55 8b}  //weight: 1, accuracy: High
        $x_1_5 = {00 73 68 65 6c 6c 5f 74 72 61 79 77 6e 64 00}  //weight: 1, accuracy: High
        $x_1_6 = "SetWindowsHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

