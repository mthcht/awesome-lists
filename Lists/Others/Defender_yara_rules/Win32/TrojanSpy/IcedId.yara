rule TrojanSpy_Win32_IcedId_A_2147729379_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/IcedId.A!bit"
        threat_id = "2147729379"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 68 66 89 48 18 59 6a 6f 66 89 48 08 59 6a 73 5e 6a 74 66 89 48 0a 59 6a 2e 66 89 48 0e 59 6a 65 5a 6a 78 66 89 48 10 59 6a 5c 66 89 48 14 59 6a 76 66 89 08 59 6a 63}  //weight: 1, accuracy: High
        $x_1_2 = {68 94 9c 50 c5 53 57 57 0b f0 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_IcedId_B_2147733528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/IcedId.B!bit"
        threat_id = "2147733528"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 b2 9f d8 b0 53 57 57 8b f0 e8 ?? ?? ?? ff 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 eb da 7b d3 53 57 57}  //weight: 2, accuracy: Low
        $x_2_2 = {33 c9 6a 73 5a 6a 74 66 89 48 ?? 59 6a 68 66 89 48 ?? 59 6a 6f 66 89 48 ?? 59 6a 2e 66 89 48 ?? 59 6a 65 66 89 48 ?? 59 6a 78 66 89 48 ?? 66 89 48 ?? 59 6a 76 66 89 48 ?? 59 6a 5c 66 89 48 ?? 59 6a 63 66 89 08 59 66 89 50}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 44 24 04 d1 c8 f7 d0 d1 c8 2d ?? ?? ?? ?? d1 c0 f7 d0 2d ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_4 = {33 f6 50 e8 ?? ?? ?? 00 30 86 ?? ?? ?? 00 46 59 81 fe ?? ?? ?? ?? 72 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_IcedId_D_2147733532_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/IcedId.D!bit"
        threat_id = "2147733532"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c7 82 be 03 00 00 83 e8 8b 45 e4 66 c7 80 c0 03 00 00 04 31 8b 4d e4 66 c7 81 c2 03 00 00 37 83 8b 55 e4 66 c7 82 c4 03 00 00 c7 04 8b 45 e4 66 c7 80 c6 03 00 00 85 c0 8b 4d e4 66 c7 81 c8 03 00 00 75 f4 8b 55 e4 8d 4d bc 66 c7 82 ca 03 00 00 c3 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_IcedId_MK_2147755498_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/IcedId.MK!MSR"
        threat_id = "2147755498"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 b0 e5 ff ff ff 4d 10 40 33 d2 8b f1 f7 f6 8d b4 15 ?? ?? ?? ?? 8a 1e 89 95 ?? ?? ?? ?? 33 d2 0f b6 c3 03 c7 8b f9 f7 f7 8b fa 8d 84 3d ?? ?? ?? ?? 8a 10 88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 85 ?? ?? ?? ?? 8a 94 15 ?? ?? ?? ?? 30 10 40 83 7d 10 00 89 85 ?? ?? ?? ?? 75 9e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_IcedId_RAI_2147760072_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/IcedId.RAI!MTB"
        threat_id = "2147760072"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 0a}  //weight: 2, accuracy: High
        $x_1_2 = {81 c7 d4 2d 0a 01 03 c8}  //weight: 1, accuracy: High
        $x_1_3 = {8a c3 80 ea 06 fe c8 f6 ea 89 7d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_IcedId_RAI_2147760072_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/IcedId.RAI!MTB"
        threat_id = "2147760072"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 c1 f8 7a 0c 01 [0-5] 83 c7 04 [0-31] 75 3f 00 03 35 ?? ?? ?? ?? 89 35}  //weight: 5, accuracy: Low
        $x_2_2 = {8b 0f 81 fa ?? ?? ?? ?? 75 [0-31] 03 35 ?? ?? ?? ?? 89 35}  //weight: 2, accuracy: Low
        $x_5_3 = {81 c7 cc cc 04 01 [0-5] 89 38 [0-5] [0-63] 0f}  //weight: 5, accuracy: Low
        $x_2_4 = {2b f0 8b 44 24 1c 1b da 8b 38 81 fe ?? ?? ?? ?? 75 [0-47] 0f b7 05}  //weight: 2, accuracy: Low
        $x_5_5 = {81 c7 b0 8d 07 01 03 f2 89 38}  //weight: 5, accuracy: High
        $x_2_6 = {03 c1 89 44 24 1c 8d 04 3e 1f 00 05}  //weight: 2, accuracy: Low
        $x_5_7 = {8b 07 05 b4 50 0a 01 89 07 83 c7 04}  //weight: 5, accuracy: High
        $x_2_8 = {0f b7 06 2b c8 8a c1 8a d1 02 c0 02 d0 02 d3 88 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

