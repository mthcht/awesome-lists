rule TrojanDropper_Win32_Perkesh_B_2147624291_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Perkesh.B"
        threat_id = "2147624291"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Perkesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 02 6a 00 6a 01 68 00 00 00 c0 50 e8}  //weight: 1, accuracy: High
        $x_1_2 = {68 3f 00 0f 00 6a 00 6a 00 e8 ?? ?? ?? ?? 89 45 ec 33 c0 55 68 ?? ?? ?? 00 64 ff 30 64 89 20 83 7d ec 00 74 75 6a 00 6a 00 6a 00 6a 00 6a 00 53 6a 00 6a 03 6a 01 6a 30 [0-32] 3d 31 04 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "%systemroot%\\Fonts\\" ascii //weight: 1
        $x_1_4 = "UpackByDwing@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Perkesh_C_2147627993_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Perkesh.C"
        threat_id = "2147627993"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Perkesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7c ea 33 c0 c3 18 00 [0-3] 33 c0 b1 ?? 8a 90 ?? ?? ?? ?? 32 d1 88 90 ?? ?? ?? ?? 40 3d ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {68 00 1e 00 00 68 ?? ?? ?? ?? 56 e8 ?? ?? ff ff 83 c4 14 85 c0 74 02}  //weight: 2, accuracy: Low
        $x_2_3 = {68 c9 23 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f8 83 c4 0c 85 ff 75 08}  //weight: 2, accuracy: Low
        $x_2_4 = {8a 0c 33 8a c3 c0 e0 ?? 2c ?? 8b fe 02 c8 33 c0 88 0c 33 83 c9 ff 43 f2 ae f7 d1 49 3b d9 72}  //weight: 2, accuracy: Low
        $x_2_5 = {74 21 8a c2 b1 ?? 2c ?? 8b fe f6 e9 8a 0c 32 02 c8 33 c0 88 0c 32}  //weight: 2, accuracy: Low
        $x_1_6 = {44 65 62 75 67 67 65 72 [0-7] 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 63 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 69 6d 61 67 65 20 66 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 6f 70 74 69 6f 6e 73 5c}  //weight: 1, accuracy: Low
        $x_1_7 = {2e 64 61 74 00 [0-32] 74 72 75 65 00 [0-5] 57 69 6e 45 78 65 63 00}  //weight: 1, accuracy: Low
        $x_1_8 = {25 73 6f 70 25 78 2e 7a [0-5] 5c 5c 2e 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

