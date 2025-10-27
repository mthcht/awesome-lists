rule Trojan_Win32_Gepys_A_2147680058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.A"
        threat_id = "2147680058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c6 40 11 49 8b 0d ?? ?? ?? ?? c6 41 12 6e 8b 15 ?? ?? ?? ?? c6 42 13 74 a1}  //weight: 10, accuracy: Low
        $x_1_2 = {2e 74 6d 70 00 47 45 54 [0-7] 50 4f 53 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_A_2147680058_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.A"
        threat_id = "2147680058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c8 ff eb 1a 0f b6 11 33 d0 81 e2 ff 00 00 00 c1 e8 08 33 04 95 ?? ?? ?? ?? 41 ff 4c 24 04 83 7c 24 04 00 7f df}  //weight: 1, accuracy: Low
        $x_1_2 = {3d d5 c6 dd c3 74 ?? 3d 10 5f e3 b4 74 ?? 3d d1 ed 7a 26}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 7e 23 ae 88 74 ?? 3d 53 4d a8 66 74 ?? 3d bc b4 b8 ee}  //weight: 1, accuracy: Low
        $x_1_4 = {bb 20 37 ef c6 c7 45 fc 20 00 00 00 ff 75 0c 53 57 6a 0b 59 e8 ?? ?? ?? ?? ff 75 0c 81 c3 47 86 c8 61}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 45 fc 8b 08 31 0e 8b 40 04 31 46 04 ?? 79 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_B_2147683545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.B"
        threat_id = "2147683545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d d5 c6 dd c3 75 04 b0 01 eb 32 3d 10 5f e3 b4 74 f5 3d d1 ed 7a 26}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 fc 20 37 ef c6 c7 45 f4 20 00 00 00 ff 75 10 ff 75 fc 57 6a 0b 59 e8 ?? ?? ?? ?? ff 75 10 81 45 fc 47 86 c8 61}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 46 24 8b 4e 28 d1 e8 85 c9 74 20 85 c0 74 1c 8d 54 41 fe 66 83 3a 5c 74 06 83 ea 02 48 75 f4 8d 04 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_B_2147683545_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.B"
        threat_id = "2147683545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 20 37 ef c6 c7 45 fc 20 00 00 00 ff 75 0c 53 57 6a 0b 59 e8 ?? ?? ?? ?? ff 75 0c 81 c3 47 86 c8 61}  //weight: 1, accuracy: Low
        $x_1_2 = {81 7d f4 4d 4f 44 53 75 3c 8b 75 f8 56 e8}  //weight: 1, accuracy: High
        $x_1_3 = {4e 8b ca 83 f9 0a 72 03 83 c1 27 80 c1 30 88 4c 35 ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_4 = {6c 6f 77 5c 00 00 00 00 6b 62 64 6f ?? ?? ?? 2e 74 6d 70}  //weight: 1, accuracy: Low
        $x_1_5 = {47 45 54 20 ?? ?? ?? ?? 50 4f 53 54 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0d 0a 68 6f 73 74 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_B_2147683545_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.B"
        threat_id = "2147683545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f cf 0f ce c7 45 fc 20 37 ef c6 c7 45 f4 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 45 fc 47 86 c8 61 ff 75 fc 2b f0 56 33 c9 e8}  //weight: 1, accuracy: High
        $x_1_3 = {6a 07 5e 33 d2 6a 1a 5f f7 f7 83 c2 61 66 89 11 83 c1 02 4e 75 ed}  //weight: 1, accuracy: High
        $x_1_4 = {03 c3 50 8d 45 ?? 50 8d 45 ?? 50 56 6a 01 56 57 89 75 ?? c7 45 ?? 00 10 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 00 53 00 68 00 65 00 6c 00 6c 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 00 00 00 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 20 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 00 00 00 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 00 74 00 6d 00 70 00 00 00 00 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {2e 00 65 00 78 00 65 00 00 00 00 00 00 00 00 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00 00 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 47 00 75 00 69 00 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Gepys_B_2147683545_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.B"
        threat_id = "2147683545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ea 47 86 c8 61 8b f2 c1 ee 0b 83 e6 03 8b 34 b7}  //weight: 1, accuracy: High
        $x_1_2 = {0f c9 0f c8 ba 20 37 ef c6 c7 45 fc 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {b8 4f ec c4 4e f7 e6 c1 ea 03 8b c2 6b c0 1a 2b f0 83 c6 61 66 89 71 02}  //weight: 1, accuracy: High
        $x_1_4 = {03 d3 52 8d 45 ?? 50 8d 4d ?? 51 56 6a 01 56 57 89 75 ?? c7 45 ?? 00 10 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 00 53 00 68 00 65 00 6c 00 6c 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 00 00 00 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 20 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 00 00 00 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 00 74 00 6d 00 70 00 00 00 00 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {2e 00 65 00 78 00 65 00 00 00 00 00 00 00 00 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00 00 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 47 00 75 00 69 00 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Gepys_B_2147683545_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.B"
        threat_id = "2147683545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d d5 c6 dd c3 75 04 b0 01 eb 32 3d 10 5f e3 b4 74 f5 3d d1 ed 7a 26}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 fc 20 37 ef c6 c7 45 f4 20 00 00 00 ff 75 10 ff 75 fc 57 6a 0b 59 e8 ?? ?? ?? ?? ff 75 10 81 45 fc 47 86 c8 61}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 46 24 8b 4e 28 d1 e8 85 c9 74 20 85 c0 74 1c 8d 54 41 fe 66 83 3a 5c 74 06 83 ea 02 48 75 f4 8d 04 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_2147740716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys!MTB"
        threat_id = "2147740716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 da 88 c1 d3 e2 8d 0c 10 89 f8 83 c8 01 03 4d 08 0f af c3 29 c7 8a 11 03 7d 08 ff 4d e4 8a 07 88 17 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_MR_2147740826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.MR!MTB"
        threat_id = "2147740826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 75 f0 33 75 ?? 03 45 ?? f7 f3 31 d6 89 15 ?? ?? ?? ?? 31 ce 03 75 ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = "(cts\\progs\\SysProg\\work\\rm\\templates\\exe\\runinmem2.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_A_2147741593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.A!MTB"
        threat_id = "2147741593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 33 33 47 60 88 04 33 46 3b 75 0c 7c f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_DSK_2147741679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.DSK!MTB"
        threat_id = "2147741679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 d9 a3 84 dd 42 00 a1 88 dd 42 00 d3 e8 05 55 75 04 00 8a 0d 84 dd 42 00 a3 88 dd 42 00 89 d8 d3 e0 03 05 84 dd 42 00 eb}  //weight: 2, accuracy: High
        $x_2_2 = {51 88 df 8a 08 fe cf 20 f9 8a 3a 00 df 08 d9 88 38 88 0a 59}  //weight: 2, accuracy: High
        $x_1_3 = "LeHzDDgCulQBzssRq" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_PDSK_2147743505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.PDSK!MTB"
        threat_id = "2147743505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 08 8a 04 18 88 45 df 43 8b 45 ec 03 45 f0 8b 55 08 0f b6 4d df 31 f1 88 0c 02 8b 45 e8 09 f0 39 45 f0 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_VDSK_2147744350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.VDSK!MTB"
        threat_id = "2147744350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d e0 8b 45 f0 8b df d3 e3 03 c7 8b f7 c1 ee 05 03 5d e4 03 75 d0 33 d8 a1 ?? ?? ?? ?? 3d 3f 0b 00 00 75 17}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 55 08 8b 4d 0c 8a 02 88 45 ff 8a 01 88 02 8a 45 ff 88 01 c9 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Gepys_PVD_2147745106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.PVD!MTB"
        threat_id = "2147745106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 45 fc 8a 02 0c 01 0f b6 f8 89 d8 99 f7 ff 0f b6 39 01 f8 88 06}  //weight: 2, accuracy: High
        $x_2_2 = {8b 55 08 01 c2 8a 02 ff 4d ec 88 45 f0 8a 01 88 02 8a 55 f0 88 11 75}  //weight: 2, accuracy: High
        $x_2_3 = {8a 17 03 45 08 ff 4d f0 88 55 d7 8a 10 88 17 8a 55 d7 88 10 8b 4d d8 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Gepys_PVS_2147745358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.PVS!MTB"
        threat_id = "2147745358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f0 81 c3 47 86 c8 61 ff 4d ec 8b 4d f4 89 5d f8 0f 85 06 00 8b 15}  //weight: 2, accuracy: Low
        $x_2_2 = {29 c1 69 c1 13 91 03 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 09 d8 69 c0 af 5c 04 00 8d 73 01 a3 06 00 8b 0d}  //weight: 2, accuracy: Low
        $x_2_3 = {01 d8 05 a5 28 01 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 31 d8 05 71 25 04 00 a3 05 00 a1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Gepys_VDK_2147747810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.VDK!MTB"
        threat_id = "2147747810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 55 e4 99 f7 7d e4 01 c1 8b 45 ec 03 4d 08 99 f7 7d e0 03 45 08 4f 8a 10 88 55 ec 8a 11 e9}  //weight: 2, accuracy: High
        $x_2_2 = {8a 28 00 dd 88 df 8a 0a d2 e7 88 f9 8a 3a 00 cf 88 38 0f b6 c5 88 d9 d3 f8 88 02}  //weight: 2, accuracy: High
        $x_1_3 = {ba 3d 24 00 00 e9 0b 00 e8 ?? ?? ?? ?? 59 e9}  //weight: 1, accuracy: Low
        $x_1_4 = {31 34 81 e9 07 00 3b c2 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gepys_PVR_2147754467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.PVR!MTB"
        threat_id = "2147754467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 c2 80 ca 01 0f af 55 fc 29 d0 8b 55 e0 01 c2 8b 45 e4 d3 e0 03 45 e0 ff 45 f4 e8 ?? ?? ?? ?? 81 7d f4 e8 07 00 00 7d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_DSA_2147757210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.DSA!MTB"
        threat_id = "2147757210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 38 80 cf 01 88 d8 f6 e7 8a 3e 28 c7 88 d9 0f b6 02 d3 f8 88 f9 88 06 88 d8 d2 e0 00 c7 88 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_DSB_2147757471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.DSB!MTB"
        threat_id = "2147757471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 e8 8d 84 0a ?? ?? ?? ?? 33 45 f0 89 45 f0 8b 4d dc 8b 55 f0 89 11 8b 45 e8 83 c0 04 89 45 e8 b9 bc 01 00 00 85 c9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_DSC_2147757476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.DSC!MTB"
        threat_id = "2147757476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 5d fc 01 d8 88 01 eb ?? 01 f8 88 06 8a 45 fc 0c 01 0f b6 f0 89 d8 99 f7 fe eb}  //weight: 1, accuracy: Low
        $x_1_2 = {89 d1 0f b6 00 8d 7b 01 99 f7 ff 88 45 fc 8a 01 0c 01 0f b6 f8 89 d8 99 f7 ff 0f b6 39 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_DSD_2147757557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.DSD!MTB"
        threat_id = "2147757557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 df 8a 08 fe cf 20 f9 8a 3a 00 df 08 d9 88 38 88 0a}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 e0 01 c2 8b 45 e4 d3 e0 8b 5d fc 03 45 e0 ff 45 f4 e8 ?? ?? ?? ?? 81 7d f4 e8 07 00 00 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_RPK_2147816053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.RPK!MTB"
        threat_id = "2147816053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 c1 31 df 03 7d 08 ff 4d f0 8a 07 88 45 cb 8a 01 88 07 8a 45 cb 88 01 8b 55 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_RPK_2147816053_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.RPK!MTB"
        threat_id = "2147816053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af 4d 10 29 ca 03 55 08 ff 4d f0 8a 0a 88 4d db 8a 08 88 0a 8a 55 db 88 10 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_RPO_2147821972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.RPO!MTB"
        threat_id = "2147821972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 38 88 dc 89 f1 fe c4 88 c8 f6 e4 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_RPS_2147823631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.RPS!MTB"
        threat_id = "2147823631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 c9 01 f7 e1 89 45 b0 8b 45 bc 8b 55 b0 29 d0 8b 55 b4 88 04 13 ff 45 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_RPP_2147830743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.RPP!MTB"
        threat_id = "2147830743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 d9 fe c9 8a 28 20 cd 88 6d fc 85 db 74 07 0f b6 0a 01 c9 eb 03 0f b6 0a 89 4d f8 8a 7d f8 88 38 8a 45 fc 08 d8 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_RPL_2147840161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.RPL!MTB"
        threat_id = "2147840161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 ac 88 45 d6 0f b6 55 d7 89 f1 d3 ea 88 14 3b 8b 45 e0 0f b6 55 d6 31 f2 88 14 03 ff 45 ec 81 7d ec e8 07 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_PAB_2147848164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.PAB!MTB"
        threat_id = "2147848164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 d8 69 c0 41 c8 04 00 31 da 69 d2 ?? ?? ?? ?? 85 db 8d b0 93 b8 00 00 8d 84 00 93 b8 00 00 0f 45 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {23 7d d4 89 c1 83 c9 01 0f af cb 03 7d ?? 29 c8 03 45 ?? 8a 0f ff 4d ?? 88 4d ?? 8a 08 88 0f 8a 4d cb 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_GNZ_2147852917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.GNZ!MTB"
        threat_id = "2147852917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d3 e2 89 50 08 89 ca 81 f2 ?? ?? ?? ?? 85 c9 89 50 0c 8d 91 ?? ?? ?? ?? 8d 1c 12 0f 45 d3 89 50 54 8b 15 ?? ?? ?? ?? 8d 59 ff 89 5d f0 89 55 ec 8d 51 01 0f af 55 ec 89 50 50 31 d2 eb 1e 89 d6 89 d7 83 ce 01 0f af f1 29 f7 89 fe 8b 7d f0 21 d7 42 8a 9f ?? ?? ?? ?? 88 5c 30 10 3b 55 ec}  //weight: 10, accuracy: Low
        $x_1_2 = "ss xhrurr>=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_GZY_2147907438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.GZY!MTB"
        threat_id = "2147907438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 d3 ff 59 12 36 30 5d 8b c9 5e 5a 59 5b c3 53 51 52}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gepys_MK_2147956088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gepys.MK!MTB"
        threat_id = "2147956088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {8b 4d 08 8b 51 04 83 ea ?? d1 ea 89 55 f4 8b 45 08 83 c0 ?? 89 45 f0 8b 4d 08 51 8b 55 10}  //weight: 15, accuracy: Low
        $x_10_2 = {89 10 8b 4d 18 8b 11 8b 45 10 8b 0c 10 03 4d 14 8b 55 18 8b 02 8b 55 10 89 0c 02}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

