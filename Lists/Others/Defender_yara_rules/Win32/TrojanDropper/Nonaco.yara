rule TrojanDropper_Win32_Nonaco_A_2147610774_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nonaco.A"
        threat_id = "2147610774"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonaco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 f8 fd ff ff 50 8d 85 30 f9 ff ff 50 8d 85 30 f5 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {74 39 ff 15 ?? ?? 40 00 6a 14 33 d2 59 f7 f1 52}  //weight: 1, accuracy: Low
        $x_1_3 = {00 84 1d 00 fc ff ff 43 ff d6 8b d0 8d bd 00 fc ff ff 83 c9 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Nonaco_C_2147611854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nonaco.C"
        threat_id = "2147611854"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonaco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 12 8b c3 99 6a 05 59 f7 f9 b0 fe 2a c2 d0 e0 00 44 1c 10}  //weight: 2, accuracy: High
        $x_2_2 = {ff d7 6a 14 59 33 d2 f7 f1 8b 35 ?? ?? 40 00}  //weight: 2, accuracy: Low
        $x_2_3 = {f7 f1 52 ff d6 ff d7 50 53 6a 11 ff 15}  //weight: 2, accuracy: High
        $x_1_4 = {74 6d 70 32 2e 72 65 67 00 3c 53 65 61 72 63 68}  //weight: 1, accuracy: High
        $x_1_5 = {72 65 67 25 73 20 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_6 = {72 65 25 73 20 22 25 73 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Nonaco_D_2147616169_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nonaco.D"
        threat_id = "2147616169"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonaco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 10
        $x_2_2 = {00 64 69 77 73 66 73 65 00}  //weight: 2, accuracy: High
        $x_2_3 = {25 73 25 73 00 61 6c 67 67}  //weight: 2, accuracy: High
        $x_1_4 = {3a 5c 74 6d 70 33 2e 72 65 67 00}  //weight: 1, accuracy: High
        $x_1_5 = {77 62 6c 6f 67 6f 6e 00 25 73 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Nonaco_G_2147624415_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nonaco.G"
        threat_id = "2147624415"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonaco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 65 00 00 67 73 76 72 33 32 20 2f 73}  //weight: 2, accuracy: High
        $x_1_2 = {75 47 8d 85 ?? ?? ff ff 68 e9 03 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 84 24 d8 00 00 00 68 e9 03 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

