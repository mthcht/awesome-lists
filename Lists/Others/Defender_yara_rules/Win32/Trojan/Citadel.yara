rule Trojan_Win32_Citadel_MA_2147843683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Citadel.MA!MTB"
        threat_id = "2147843683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Citadel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 1d d1 b7 40 00 8b 4d ec 33 ce 21 1d f9 b7 40 00 41 81 35 89 b7 40 00 15 b8 40 00 33 ce 89 4d ec 40 8b 0d a0 b1 40 00 89 3d 15 b8 40 00 8b 89 94 01 00 00 bb dd 67 00 00 8b 19 8b cb 8b 5b 3c 3b 44 0b 28 c7 05 7d b7 40 00 41 48 00 00 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Citadel_MB_2147843753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Citadel.MB!MTB"
        threat_id = "2147843753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Citadel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 55 e8 29 d2 88 55 e8 0f b7 45 e4 c1 e0 10 89 45 e0 8b 45 e0 c1 e8 03 66 89 45 e4 0f b6 55 e8 33 55 e0 81 ea ?? ?? ?? ?? 0f b6 0b 8b 45 f8 88 0c 10 0f b6 55 e8 0f b7 4d e4 09 ca 81 f2 ?? ?? ?? ?? 88 55 dc 66 81 7d e4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Citadel_MC_2147843834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Citadel.MC!MTB"
        threat_id = "2147843834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Citadel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e3 51 41 00 00 55 8b ec 83 ec 10 81 25 [0-11] c7 45 [0-8] 81 05 [0-11] c7 45 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {75 62 74 7a 78 70 44 4b 42 59 49 48 52 6c 45 4b 51 42 4e 49 67 76 6d 53 5f 13 40 00 00 00 00 00 18 84 40 00 20 84 40 00 64 82 40 00 5e 72 12 dc f0 e1 49 e0 fa e1}  //weight: 1, accuracy: High
        $x_1_3 = {b0 e1 f6 e1 bc e1 49 e0 bd e1 95 24 92 25 82 35 83 36 f3 06 f0 07 b2 e1 fd e1 49 e0 fd e1 b5 e1 c7 e1 b0 e1 e0 e1 bc e1 49 e0 bd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Citadel_MBHK_2147852449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Citadel.MBHK!MTB"
        threat_id = "2147852449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Citadel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 08 0f bf 11 33 c9 3b d0 0f 94 c1 f7 d9 8b f1 8d 4d 98}  //weight: 1, accuracy: High
        $x_1_2 = {e0 44 40 00 ec 16 40 00 00 f0 30 00 00 ff ff ff 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Citadel_A_2147896862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Citadel.A!MTB"
        threat_id = "2147896862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Citadel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c1 33 d2 b9 ?? ?? ?? ?? f7 f1 8b cb 2b c8 8b 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Citadel_B_2147898700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Citadel.B!MTB"
        threat_id = "2147898700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Citadel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 44 24 18 00 51 40 00 c7 44 24 1c fc 50 40 00 c7 44 24 20 f8 50 40 00 c7 44 24 24 f4 50 40 00 c7 44 24 28 f0 50 40 00 c7 44 24 2c ec 50 40 00 c7 44 24 30 e8 50 40 00 c7 44 24 34 e4 50 40 00 c7 44 24 38 e0 50 40 00 c7 44 24 3c dc 50 40}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

