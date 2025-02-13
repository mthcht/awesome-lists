rule TrojanDropper_Win32_Ilomo_A_2147600105_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Ilomo.gen!A"
        threat_id = "2147600105"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Ilomo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 1e 40 00 44 1e 40 00 9e 20 40 00 ce 20 40 00 0b 22 40 00 04 00 22 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "ExpandEnvironmentStringsA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Ilomo_C_2147621724_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Ilomo.C"
        threat_id = "2147621724"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Ilomo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 fe 4b 45 52 4e 8b 78 04 75 0d 81 ff 45 4c 33 32 75 22 89 5d f4 fe c1 81 fe 6e 74 64 6c 75 11 81 ff 6c 2e 64 6c 75 09}  //weight: 1, accuracy: High
        $x_1_2 = {75 f6 8b 50 04 56 81 e2 00 00 ff ff 57 32 c9 81 3a 4d 5a 90 00 75 4f 8b 42 3c 3d 00 10 00 00 73 45}  //weight: 1, accuracy: High
        $x_2_3 = {88 5d e1 c6 45 e2 6c 88 5d e3 88 5d e4 88 5d e5 66 c7 45 f0 18 00 66 c7 45 f2 1a 00 ff d0 8b 45 fc 5b c9 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Ilomo_B_2147621725_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Ilomo.B"
        threat_id = "2147621725"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Ilomo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {53 6a 01 88 18 c6 40 fd 64 c6 40 fe 61 c6 40 ff 74 68 00 00 00 80}  //weight: 4, accuracy: High
        $x_4_2 = {8b f0 83 fe ff 74 3c 6a 40 68 00 30 00 00 56 53 ff 15 ?? ?? ?? ?? 3b c3 89 45 f8 74 26}  //weight: 4, accuracy: Low
        $x_3_3 = "%ComSpec% /c dir /s %SystemRoot%>nul && del \"" ascii //weight: 3
        $x_1_4 = {31 32 33 34 35 00}  //weight: 1, accuracy: High
        $x_1_5 = "CLSID\\{0002DF01-0000-0000-C000-000000000046}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

