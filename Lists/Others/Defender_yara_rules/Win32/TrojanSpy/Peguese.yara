rule TrojanSpy_Win32_Peguese_A_2147658162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Peguese.A"
        threat_id = "2147658162"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Peguese"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 83 b4 03 00 00 19 00 83 bb ?? 03 00 00 02 75 ?? 8d 55 f8 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 55 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {70 72 6f 6a 65 63 74 31 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Peguese_B_2147658163_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Peguese.B"
        threat_id = "2147658163"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Peguese"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 95 f4 fe ff ff b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 85 f4 fe ff ff e8 ?? ?? ?? ff 50 8b 45 fc 8b 80 cc 03 00 00 50}  //weight: 1, accuracy: Low
        $x_1_2 = {70 6a 63 74 32 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Peguese_C_2147658164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Peguese.C"
        threat_id = "2147658164"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Peguese"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 95 20 ff ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 20 ff ff ff e8 ?? ?? ?? ?? 50 8b 45 fc 8b 80 20 04 00 00}  //weight: 1, accuracy: Low
        $x_5_2 = {50 57 33 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74}  //weight: 5, accuracy: High
        $x_5_3 = "AsDullhill" ascii //weight: 5
        $x_1_4 = {6a 30 56 8d 95 ?? fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 85 ?? fe ff ff e8 ?? ?? ?? ?? 50 53 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 10 53 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

