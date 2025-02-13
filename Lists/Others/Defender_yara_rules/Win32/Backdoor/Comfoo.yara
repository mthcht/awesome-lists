rule Backdoor_Win32_Comfoo_B_2147643783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Comfoo.B"
        threat_id = "2147643783"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Comfoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ff 08 7d 02 8b f7 33 c0 85 f6 7e 15 8a 88 ?? ?? ?? ?? 8a 54 04 14 32 d1 88 54 04 14 40 3b c6 7c eb}  //weight: 1, accuracy: Low
        $x_1_2 = "\\\\.\\DevCtrlKrnl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Comfoo_C_2147655750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Comfoo.C"
        threat_id = "2147655750"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Comfoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 57 53 56 ff 15 ?? ?? ?? ?? 85 c0 74 0f 81 fb 08 21 22 00 75 07 c7 45 ?? 01 00 00 00 c7 45 ?? ff ff ff ff e8 ?? ?? 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = "THIS324NEWGAME" ascii //weight: 1
        $x_1_3 = "perfdi.ini" ascii //weight: 1
        $x_1_4 = "\\usbak.sys" ascii //weight: 1
        $x_1_5 = "\\\\.\\DevCtrlKrnl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Comfoo_D_2147669238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Comfoo.D"
        threat_id = "2147669238"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Comfoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 c4 08 89 45 fc eb 1f 8b 45 f8 6b c0 32 05}  //weight: 2, accuracy: High
        $x_2_2 = {75 09 8b 4d f0 8b 51 04 89 55 f8 eb 8a 83 7d dc 00 74 0a 8b 45 dc 50 ff 15}  //weight: 2, accuracy: High
        $x_1_3 = {5c 73 63 72 65 65 6e 62 69 74 2e 62 6d 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 59 47 41 4d 45 48 41 56 45 53 54 41 52 54 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 6d 73 74 65 6d 70 2e 74 65 6d 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {70 65 72 66 64 69 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_7 = {6d 73 70 6b 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {54 31 59 39 34 33 6a 49 68 6b 00}  //weight: 1, accuracy: High
        $x_1_9 = {63 3a 5c 74 65 6d 70 5c 61 62 63 61 62 63 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

