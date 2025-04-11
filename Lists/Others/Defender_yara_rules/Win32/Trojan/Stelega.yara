rule Trojan_Win32_Stelega_AA_2147764351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.AA!MTB"
        threat_id = "2147764351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 05 1a 00 00 68 00 f0 40 00 ff 55 fc 6a 00 68 00 f0 40 00 6a 00 ff 55 d4}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 d0 83 c2 01 89 55 d0 81 7d d0 05 1a 00 00 0f 83 ?? ?? ?? ?? 8b 45 d0 8a 88 00 f0 40 00 88 4d df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelega_MK_2147772471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.MK!MTB"
        threat_id = "2147772471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b2 68 32 c8 2a d1 2a d0 c0 ca 02 32 d0 fe ca 02 d0 f6 d2 32 d0 d0 ca f6 da 32 d0 02 d0 d0 c2 80 f2 2c f6 d2 88 94 [0-5] 40 3d [0-2] 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelega_DE_2147779245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.DE!MTB"
        threat_id = "2147779245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 39 8e e3 38 f7 eb c1 fa 02 8b c2 c1 e8 1f 03 c2 8a c8 c0 e0 03 02 c8 8a c3 02 c9 2a c1 04 05 32 c5 88 04 1e 43 8a 2c 3b 84 ed 75}  //weight: 1, accuracy: High
        $x_1_2 = "encrypted_key" ascii //weight: 1
        $x_1_3 = "Ftbi}oMeakBqabzzrA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelega_RW_2147782387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RW!MTB"
        threat_id = "2147782387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 09 ff e8 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 29 f8 31 0b 01 f8 09 c7 43 81 c0 12 6c ea ad}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelega_RW_2147782387_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RW!MTB"
        threat_id = "2147782387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ee f0 85 07 86 e8 ?? ?? ?? ?? 42 31 19 89 d2 01 d6 41 09 d2 39 c1 75}  //weight: 1, accuracy: Low
        $x_1_2 = {bb b2 c9 4e 00 40 e8 ?? ?? ?? ?? b8 14 14 3e 71 31 1e 21 c0 49 81 c6 01 00 00 00 21 c1 39 fe 75 df}  //weight: 1, accuracy: Low
        $x_1_3 = {81 ef 47 82 38 7e 31 02 09 cb 89 cb 42 49 f7 d1 81 c6 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {81 e9 bc 68 1d 4f 01 d9 31 30 b9 a5 95 dc d9 bf c8 c8 fe 14 29 df 40 01 cf 81 c1 af 07 21 4c}  //weight: 1, accuracy: High
        $x_1_5 = {89 ca 01 d2 81 c2 01 00 00 00 31 3b 81 ea 01 00 00 00 81 e9 56 51 f4 b4 01 f6 43 21 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Stelega_RW_2147782387_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RW!MTB"
        threat_id = "2147782387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 c0 43 81 c0 ?? ?? ?? ?? 31 0e 48 f7 d3 81 c3 71 f6 8f 39 81 c6 02 00 00 00 89 d8 21 db bb ?? ?? ?? ?? 39 fe 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {29 f0 be a9 d1 a8 fd 31 11 21 f0 81 c6 ?? ?? ?? ?? 09 f6 81 c1 02 00 00 00 81 e8 ?? ?? ?? ?? 39 f9 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {29 f7 81 c7 ?? ?? ?? ?? be 16 2a 95 05 89 f7 31 02 81 c6 ?? ?? ?? ?? 4f 89 f7 81 c2 02 00 00 00 29 f6 be ?? ?? ?? ?? 39 ca 7c}  //weight: 1, accuracy: Low
        $x_1_4 = {29 fe 81 c7 1b 61 0d ee 01 f7 31 11 f7 d6 81 c1 02 00 00 00 29 ff 39 c1 7c ?? 29 ff 4e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Stelega_RW_2147782387_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RW!MTB"
        threat_id = "2147782387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 c9 89 c9 e8 ?? ?? ?? ?? 21 c1 21 c8 31 3e 09 c0 81 c6 02 00 00 00 b9 e8 66 ad a6 81 e9 5c 3e 9d 49 81 c0 37 07 49 e7 39 d6 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {be a2 72 84 00 81 e8 01 00 00 00 40 e8 ?? ?? ?? ?? 48 01 c7 31 33 48 57 8b 04 24 83 c4 04}  //weight: 1, accuracy: Low
        $x_1_3 = {01 fe 4f e8 ?? ?? ?? ?? 09 f6 bf a6 bd bd 7a 01 f6 31 03 09 f7 bf ed 80 34 ef 01 f7 81 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c4 04 81 e9 9c 70 99 09 e8 ?? ?? ?? ?? 29 f9 01 f9 31 18 4f 21 f9 81 c0 02 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {be 83 07 9c 38 e8 ?? ?? ?? ?? 83 ec 04 c7 04 24 c0 a0 7b 3e 8b 34 24 83 c4 04 31 3b 81 ee 01 00 00 00 43}  //weight: 1, accuracy: Low
        $x_1_6 = {81 ee 3a 1b 3e 24 e8 ?? ?? ?? ?? 81 c6 57 9a c7 c2 89 f2 31 1f 21 f2 29 f2 81 c7 02 00 00 00 81 ea 80 31 5b d8 39}  //weight: 1, accuracy: Low
        $x_1_7 = {bb 3d c6 cc c7 31 06 68 1d c5 0a 27 8b 14 24 83 c4 04 01 d3 46 01 d2 01 d3}  //weight: 1, accuracy: High
        $x_1_8 = {bf a8 03 c4 05 01 d2 e8 ?? ?? ?? ?? 4a 21 d7 31 18 bf 60 92 79 7e 40 09 ff 01 d2}  //weight: 1, accuracy: Low
        $x_1_9 = {bb dc 87 5d 00 29 ff e8 ?? ?? ?? ?? 81 e8 01 00 00 00 31 1a 89 c7 81 e8 36 cb b2 f2 29 f8 81 c2 02 00 00 00}  //weight: 1, accuracy: Low
        $x_1_10 = {81 c7 8f b0 92 b7 89 cf 21 f9 e8 ?? ?? ?? ?? 81 c1 4c cd 46 cf 31 06 81 e9 8e c3 40 98 46 81 c7 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Stelega_RM_2147782681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RM!MTB"
        threat_id = "2147782681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c7 38 33 fa 44 e8 ?? ?? ?? ?? 89 d7 81 c7 15 ac e1 5d 89 ff 31 06 09 d7 81 c6 01 00 00 00 01 fa 39 ce 75}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ef 76 eb 7c bf 48 e8 ?? ?? ?? ?? 81 c0 dd 1f dc 4c 31 16 68 ?? ?? ?? ?? 58 48 46 01 ff 81 ef}  //weight: 1, accuracy: Low
        $x_1_3 = {81 c0 c1 78 8b ee e8 ?? ?? ?? ?? 09 c1 31 16 21 c0 46 51 58 29 c1}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c4 04 e8 ?? ?? ?? ?? 01 c9 09 c9 21 c9 31 16 bb 3f df eb 74 01 cb 4b 46 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Stelega_RM_2147782681_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RM!MTB"
        threat_id = "2147782681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "1oivviovidwopopin.info" ascii //weight: 10
        $x_10_2 = "C:\\Work\\finder2\\preparer\\Release\\preparer.pdb" ascii //weight: 10
        $x_1_3 = "Malformed encoding found" ascii //weight: 1
        $x_1_4 = "\\Google\\Chrome\\User Data" ascii //weight: 1
        $x_1_5 = "\\Default\\History" ascii //weight: 1
        $x_1_6 = "Cookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelega_RTH_2147783733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RTH!MTB"
        threat_id = "2147783733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 29 df 4f e8 ?? ?? ?? ?? 21 db 01 df 81 eb 01 96 0a 95 31 02 89 df}  //weight: 1, accuracy: Low
        $x_1_2 = {29 f6 09 f3 e8 ?? ?? ?? ?? 4e 31 0a 83 ec 04 89 1c 24 5b 42 83 ec 04}  //weight: 1, accuracy: Low
        $x_1_3 = {47 09 ff b9 27 bb 51 b1 e8 ?? ?? ?? ?? 29 c9 09 f9 31 32 89 f9 89 c9 09}  //weight: 1, accuracy: Low
        $x_1_4 = {81 ee 6d 4e 6c c5 31 13 21 c9 81 ee 36 45 63 b5 21 f6 43 29 f6 41 39 c3 75 d3}  //weight: 1, accuracy: High
        $x_1_5 = {bb 4a f8 f9 b9 89 db 31 10 bb bf 0d ac 94 21 fb 81 ef 88 d1 bd 87 40 21 fb}  //weight: 1, accuracy: High
        $x_1_6 = {81 ea 1d eb ee 56 e8 ?? ?? ?? ?? 40 21 d0 31 0f 21 d2 21 c2 48 47 81 e8}  //weight: 1, accuracy: Low
        $x_1_7 = {ba c2 d6 f7 9b e8 ?? ?? ?? ?? 21 c2 21 c0 48 31 19 81 c0 e7 16 00 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Stelega_RF_2147786743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RF!MTB"
        threat_id = "2147786743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 89 f7 e8 ?? ?? ?? ?? 01 f6 01 f6 09 f6 31 03 81 ee 80 d8 7d d6 01 ff 81 ee}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c1 62 fe 43 51 81 e9 01 00 00 00 31 1f be 63 a3 dc 61 81 e9 30 31 01 56 f7 d1 47 89 c1 f7 d1 89 f1 81 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Stelega_RF_2147786743_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RF!MTB"
        threat_id = "2147786743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "File corrupted" ascii //weight: 1
        $x_10_2 = "it's infected by a Virus or cracked. This file won't work anymore" ascii //weight: 10
        $x_1_3 = "WINHTTP.dll" ascii //weight: 1
        $x_1_4 = "PathFileExistsW" ascii //weight: 1
        $x_1_5 = "SHGetFolderPathA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelega_RT_2147788009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RT!MTB"
        threat_id = "2147788009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c2 83 e0 03 0f b6 80 ?? ?? ?? ?? 30 82 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8d 80 ?? ?? ?? ?? 03 c2 83 e0 03 0f b6 80 ?? ?? ?? ?? 30 82 ?? ?? ?? ?? 83 c2 06 81 fa a0 bb 0d 00 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelega_RT_2147788009_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RT!MTB"
        threat_id = "2147788009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sFkDi@s@g@hHn<q@k<t<f9qAkHe=f:r" ascii //weight: 1
        $x_1_2 = "l<t<i=qBh<s@g@jBrAm<s9p=t<hCkEg>hGm" ascii //weight: 1
        $x_1_3 = "lEh9jEe@r@qDeFl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelega_RT_2147788009_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RT!MTB"
        threat_id = "2147788009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 5d fc 31 4d ?? 8b 5d ?? c7 05 ?? ?? ?? ?? 01 00 00 00 01 1d ?? ?? ?? ?? ff 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5b 8b e5 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c1 8a 10 00 00 8b 55 ?? 8b 02 2b c1 8b 4d ?? 89 01 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 4c 10 ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 c1 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelega_RMA_2147809867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RMA!MTB"
        threat_id = "2147809867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SetCurrentDirectoryW" ascii //weight: 1
        $x_1_2 = "OutputDebugStringW" ascii //weight: 1
        $x_1_3 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_4 = "\\mailslot" ascii //weight: 1
        $x_10_5 = "Q06NqkmNniFA29P9c14PFtq3itVDUMoKLXIa5UXmzF" ascii //weight: 10
        $x_10_6 = "pTFEHvzZNr9iSR4SIEPk0hHcKL5FHJ63ngQq88PhPJb" ascii //weight: 10
        $x_10_7 = "efFVU6uIcOLT7VEJBwygqtZUUuy0z8a3L4fP3XOvolP7GUq0k" ascii //weight: 10
        $x_10_8 = "xLvvTJXjEBD0rozk7ky8KrQscSKZ6SBmLavFaMdaqDd" ascii //weight: 10
        $x_10_9 = "mQ84aZIJtkk7D8uxuJE2yRd1bdnGeoNfOjB3" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Stelega_DP_2147819991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.DP!MTB"
        threat_id = "2147819991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 08 8b 94 24 ?? ?? ?? ?? 8b 4c 24 0c 2b d0 03 ca 89 8c 24 ?? ?? ?? ?? 8b 4c 24 10 8b c2 d3 e8 89 94 24 ?? ?? ?? ?? 89 44 24 08 8b 84 24 ?? ?? ?? ?? 01 44 24 08 8b c2 c1 e0 04 03 84 24 ?? ?? ?? ?? 33 84 24 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 21 01 00 00 89 84 24 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelega_RB_2147844002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RB!MTB"
        threat_id = "2147844002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff 2b 45 f8 88 45 ff 0f b6 4d ff f7 d9 88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelega_RI_2147849277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.RI!MTB"
        threat_id = "2147849277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\Project1.vbp" wide //weight: 1
        $x_1_2 = "Comodo\\IceDragon" wide //weight: 1
        $x_1_3 = "8pecxstudios\\Cyberfox" wide //weight: 1
        $x_1_4 = "NETGATE Technologies\\BlackHawK" wide //weight: 1
        $x_1_5 = "Moonchild Productions\\Pale Moon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelega_EAXC_2147934437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.EAXC!MTB"
        threat_id = "2147934437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b1 96 f6 d2 2a d0 c0 c2 03 02 d0 f6 da 80 f2 2b 80 ea 58 f6 d2 32 d0 c0 c2 02 02 d0 32 d0 2a ca 32 c8 88 88 ?? ?? ?? ?? 40 3d 05 50 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stelega_EANX_2147938593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelega.EANX!MTB"
        threat_id = "2147938593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b1 09 f6 d0 32 c2 2a c8 80 f1 c6 2a ca d0 c9 80 f1 8e f6 d9 80 f1 a8 88 8a ?? ?? ?? ?? 42 81 fa 05 50 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

