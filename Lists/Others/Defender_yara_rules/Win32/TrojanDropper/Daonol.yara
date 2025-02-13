rule TrojanDropper_Win32_Daonol_B_2147803897_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Daonol.B"
        threat_id = "2147803897"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 79 73 61 75 64 69 6f 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 75 78 00}  //weight: 1, accuracy: High
        $x_2_3 = "miekiemoes rules" wide //weight: 2
        $x_2_4 = {4e 83 fe 00 7c 16 b8 19 00 00 00 e8 ?? ?? ff ff 83 c0 61 88 03 43 4e 83 fe ff 75 ea c6 03 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Daonol_D_2147803901_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Daonol.D"
        threat_id = "2147803901"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " ExIsT \"C:\\_." ascii //weight: 1
        $x_1_2 = {64 65 6c 20 22 43 3a 5c ?? 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_2_3 = "Miekiemoes rules" wide //weight: 2
        $x_1_4 = {8a 4c 02 ff 80 f1 ?? 88 4c 02 ff 4a 75 f2 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Daonol_E_2147803949_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Daonol.E"
        threat_id = "2147803949"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 79 73 61 75 64 69 6f 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 75 78 00}  //weight: 1, accuracy: High
        $x_1_3 = ":\\_.e" ascii //weight: 1
        $x_2_4 = {80 f1 d5 88 4c 02 ff 4a 75 f2 c3}  //weight: 2, accuracy: High
        $x_2_5 = {c7 44 24 04 2e 2e 5c 00 54 68 3f 00 0f 00 6a 00 b8 ?? ?? ?? ?? ba 37 00 00 00}  //weight: 2, accuracy: Low
        $x_2_6 = {4e 83 fe 00 7c 16 b8 19 00 00 00 e8 ?? ?? ff ff 83 c0 61 88 03 43 4e 83 fe ff 75 ea c6 03 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

