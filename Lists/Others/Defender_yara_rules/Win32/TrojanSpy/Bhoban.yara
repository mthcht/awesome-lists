rule TrojanSpy_Win32_Bhoban_A_2147650442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bhoban.A"
        threat_id = "2147650442"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bhoban"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "5D424145460E1A19545" wide //weight: 8
        $x_4_2 = "1B5E5153475150185C5B" wide //weight: 4
        $x_2_3 = "504215704B485D594A5D416A665046475447" wide //weight: 2
        $x_2_4 = "665E505959147159567A515254554C18655C5042" wide //weight: 2
        $x_2_5 = "627B6A7D6179796972706777737C7D7B67" wide //weight: 2
        $x_2_6 = "7D7D706C6A787A7574796C75707570717D706966" wide //weight: 2
        $x_2_7 = "1A4247544C061B424D41" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Bhoban_2147659646_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bhoban"
        threat_id = "2147659646"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bhoban"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {85 c0 74 11 8b 55 08 c6 02 e9 8b 45 0c 2b c2 83 e8 05 89 42 01 c9 c2 08 00}  //weight: 5, accuracy: High
        $x_5_2 = {b8 44 00 00 00 e8 19 00 00 00 33 c9 89 4d e4 a1 ?? ?? 00 10 83 c0 11 ff e0 51 b9 56 01 00 00 8b cf 59 c3}  //weight: 5, accuracy: Low
        $x_1_3 = {8d 49 02 66 39 19 75 f0 3d e0 1e 00 00 75 5f c7 44 3c 1c 01 00 00 80 c7 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Bhoban_B_2147679533_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bhoban.B"
        threat_id = "2147679533"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bhoban"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {74 0a ff 45 e8 ff 4d fc 74 21 eb e2 8b 45 e8 d1 e0 03 45 ec 03 45 08 0f b7 00 c1 e0 02 03 45 f0 03 45 08}  //weight: 10, accuracy: High
        $x_10_2 = {00 10 85 c0 74 11 8b 55 08 c6 02 e9 8b 45 0c 2b c2 83 e8 05 89 42 01 c9 c2 08 00}  //weight: 10, accuracy: High
        $x_10_3 = {8a 11 80 ca 20 03 c2 90 8d 49 02 66 39 19 75 f0 3d e0 1e 00 00 75 5e c7 44 3c 1c 01 00 00 80}  //weight: 10, accuracy: High
        $x_1_4 = "CloseGuard" ascii //weight: 1
        $x_1_5 = {00 61 64 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

