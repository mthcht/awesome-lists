rule PWS_Win32_Mapdimp_C_2147611046_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mapdimp.C"
        threat_id = "2147611046"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mapdimp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e4 54 41 32 45 c7 45 e8 64 69 74 00 89 5d ec c7 45 d4 54 46 72 6d c7 45 d8 4c 6f 67 4f c7 45 dc 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a f4 ff 75 fc ff 15 ?? ?? ?? ?? 3d 9c 10 01 00 75 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Mapdimp_A_2147611900_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mapdimp.A"
        threat_id = "2147611900"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mapdimp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 6a 00 6a fc ff 75 dc ff 15 ?? ?? ?? ?? 6a 00 8d 45 d8 50 6a 04 8d 45 f0 50 ff 75 dc ff 15 ?? ?? ?? ?? 81 7d f0 02 00 00 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 00 32 01 8b 4d 08 03 4d f8 88 01 8b 45 fc 40 89 45 fc 8b 45 10 03 45 14 39 45 fc 72 08 8b 45 10 89 45 f4 eb 06}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 f0 64 26 74 3d c7 45 f4 25 73 26 71 c7 45 f8 3d 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Mapdimp_B_2147611901_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mapdimp.B"
        threat_id = "2147611901"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mapdimp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 19 03 c2 30 18 41 3b ce 72 02 8b cf 42 3b 55 0c 7c ea}  //weight: 1, accuracy: High
        $x_1_2 = {bb 8c 00 00 00 83 c0 f8 33 d2 8b cb [0-3] f7 f1 85 c0 7e}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c0 f8 8b cb f7 f1 01 5d ?? 83 c4 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Mapdimp_D_2147615066_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mapdimp.D"
        threat_id = "2147615066"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mapdimp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {6a 02 57 6a fc 53 ff d6 8d 45 f8 57 50 8d 45 f4 6a 04 50 53 8b 1d ?? ?? ?? ?? ff d3 81 7d f4 ?? ?? ?? ?? 74 0e}  //weight: 4, accuracy: Low
        $x_1_2 = "verclsid" ascii //weight: 1
        $x_1_3 = {c7 45 ec 6f 6b 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 ec 5f 4d 42 00 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Mapdimp_E_2147615067_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mapdimp.E"
        threat_id = "2147615067"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mapdimp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {83 c1 f8 51 50 ff 75 08 ff d6 8b 45 fc bb 8c 00 00 00 83 c0 f8 33 d2 8b cb f7 f1 85 c0 7e 33}  //weight: 4, accuracy: High
        $x_1_2 = "verclsid" ascii //weight: 1
        $x_1_3 = {c7 45 ec 6f 6b 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 ec 5f 4d 42 00 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Mapdimp_F_2147615068_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mapdimp.F"
        threat_id = "2147615068"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mapdimp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {83 c0 f8 50 56 ff 75 08 ff d3 8b 45 fc bb 8c 00 00 00 83 c0 f8 33 d2 8b cb 89 7d f0 f7 f1 85 c0 7e 36}  //weight: 4, accuracy: High
        $x_1_2 = "ADVAPI32.dll" ascii //weight: 1
        $x_1_3 = {c7 45 ec 6f 6b 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 ec 5f 4d 42 00 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

