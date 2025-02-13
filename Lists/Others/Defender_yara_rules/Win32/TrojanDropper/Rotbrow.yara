rule TrojanDropper_Win32_Rotbrow_A_2147683859_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rotbrow.A"
        threat_id = "2147683859"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rotbrow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 04 8b 0e eb 02 8b ce bf ?? ?? 00 00 66 33 b8 ?? ?? ?? ?? 83 c0 02 66 89 7c 08 fe 83 f8 ?? 72 dc 8b c6}  //weight: 5, accuracy: Low
        $x_1_2 = {62 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 46 00 6f 00 72 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 5f 00 62 00 68 00 6f 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {2e 3f 41 56 69 6e 6a 65 63 74 6f 72 40 70 72 6f 74 65 63 74 69 6f 6e 40 40 00}  //weight: 1, accuracy: High
        $x_2_6 = "\\Jenkins\\jobs\\babylon-2.7\\workspace\\output\\Release\\protector.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Rotbrow_B_2147683860_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rotbrow.B"
        threat_id = "2147683860"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rotbrow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 04 8b 03 eb 02 8b c3 ba ?? ?? 00 00 66 33 14 75 ?? ?? ?? ?? 46 66 89 54 70 fe 83 fe ?? 72 d2 8b c7}  //weight: 5, accuracy: Low
        $x_1_2 = {62 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 46 00 6f 00 72 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {42 00 52 00 4f 00 57 00 53 00 45 00 52 00 4d 00 4e 00 47 00 52 00 53 00 45 00 54 00 54 00 49 00 4e 00 47 00 53 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 5f 00 62 00 68 00 6f 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {62 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 2e 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 50 52 4f 54 45 43 54 5f 58 4d 4c 5f 4e 41 4d 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Rotbrow_F_2147683864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rotbrow.F"
        threat_id = "2147683864"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rotbrow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 6f 64 65 63 6f 6e 73 74 4f 6e 65 43 6c 69 63 6b 50 6c 75 67 69 6e 20 70 6c 75 67 69 6e 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 68 72 6f 6d 65 50 72 6f 74 65 63 74 69 6f 6e 45 6e 61 62 6c 65 64 00}  //weight: 1, accuracy: High
        $x_1_4 = "application/x-vnd.protector.settingstracker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Rotbrow_G_2147683917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rotbrow.G"
        threat_id = "2147683917"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rotbrow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 33 04 75 ?? ?? ?? ?? 56 8b cb 0f b7 f8 e8 ?? ?? ?? ?? 46 66 89 38 83 fe ?? 72 df 05 00 b8 ?? ?? 00 00}  //weight: 5, accuracy: Low
        $x_1_2 = {62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 64 00 62 00 61 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 2e 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 00 50 00 52 00 4f 00 54 00 45 00 43 00 54 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 00 61 00 6d 00 70 00 61 00 69 00 67 00 6e 00 69 00 64 00 00 00 00 00 73 00 75 00 62 00 69 00 64 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

