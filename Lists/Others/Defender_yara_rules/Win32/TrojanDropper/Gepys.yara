rule TrojanDropper_Win32_Gepys_A_2147680240_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gepys.A"
        threat_id = "2147680240"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 ea 47 86 c8 61 8b f2 c1 ee 0b 83 e6 03 8b 34 b7}  //weight: 1, accuracy: High
        $x_1_2 = {0f c9 0f c8 ba 20 37 ef c6 c7 45 fc 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {b8 4f ec c4 4e f7 e6 c1 ea 03 8b c2 6b c0 1a 2b f0 83 c6 61 66 89 71 02}  //weight: 1, accuracy: High
        $x_1_4 = {41 00 70 00 70 00 49 00 6e 00 69 00 74 00 5f 00 44 00 4c 00 4c 00 73 00 00 00 00 00 4c 00 6f 00 61 00 64 00 41 00 70 00 70 00 49 00 6e 00 69 00 74 00 5f 00 44 00 4c 00 4c 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {2e 00 74 00 6d 00 70 00 00 00 00 00 6a 00 61 00 76 00 61 00 5f 00 75 00 70 00 64 00 61 00 74 00 65 00 5f 00 00 00 00 00 72 00 75 00 6e 00 61 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 53 00 68 00 65 00 6c 00 6c 00 20 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 00 00 00 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 20 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 00 00 00 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00 00 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 47 00 75 00 69 00 64 00 00 00 00 00 00 00 5c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDropper_Win32_Gepys_DJ_2147742179_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gepys.DJ!MTB"
        threat_id = "2147742179"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d 08 8a 0c 37 89 df 46 d3 e7 89 7d d8 8b 7d d4 03 4d d8 88 0c 07 8b 4d d0 01 f1 39 d0 0f 44 f1 40 3b 45 f0}  //weight: 1, accuracy: High
        $x_1_2 = {01 f0 f7 f1 8b 45 e4 88 d9 d3 e0 05 c3 77 03 00 d3 e8 b9 80 0d 01 00 89 d6 89 15}  //weight: 1, accuracy: High
        $x_1_3 = {8b 7d 08 8a 0c 37 46 8b 7d ec 01 d9 3b 45 d8 88 0c 07 8d 0c 16 0f 44 f1 40 3b 45 f0}  //weight: 1, accuracy: High
        $x_1_4 = {f7 f1 88 d9 d3 6d ec 8b 4d ec 81 c1 3f 9c 04 00 d3 e3 8d 04 0b b9 bb ff 00 00 89 d6 89 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Gepys_GC_2147743010_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gepys.GC!MTB"
        threat_id = "2147743010"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f9 89 f2 d3 e2 01 d7 f7 e7 89 45 ?? a3 30 00 a3 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? b8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 8b 4d 0c 8a 02 88 45 ff 8a 01 88 02 8a 45 ff 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Gepys_RL_2147744030_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gepys.RL!MTB"
        threat_id = "2147744030"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 e0 69 c0 0f e9 00 00 8b 0d ?? ?? ?? ?? 31 d2 80 c9 01 a3 ?? ?? ?? ?? 89 d8 f7 f1 03 05 ?? ?? ?? ?? 69 c0 29 cd 02 00 01 d8 31 d2 05 af 48 04 00 8d 4b 01 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? f7 f1 69 c0 ef e0 04 00 88 d9 d3 e8 05 29 14 03 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 31 d2 09 d8 8b 0d ?? ?? ?? ?? 05 c3 43 01 00 80 c9 01 a3 ?? ?? ?? ?? 89 d8 f7 f1 b9 4c ff 00 00 03 05 ?? ?? ?? ?? 31 d2 f7 f1 89 15}  //weight: 2, accuracy: Low
        $x_2_2 = {29 c1 31 d2 89 c8 b9 9e 00 01 00 f7 f1 a1 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 01 d8 31 d2 05 b5 92 02 00 8d 4b 01 a3 ?? ?? ?? ?? f7 f1 b9 b3 fe 00 00 31 d2 f7 f1 b9 89 0b 01 00 a1 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 09 d8 31 d2 f7 f1 b9 70 03 01 00 8d 43 ff 89 15 ?? ?? ?? ?? 23 05 ?? ?? ?? ?? 31 d2 f7 f1 8b 0d ?? ?? ?? ?? 89 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Gepys_DQ_2147817682_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gepys.DQ!MTB"
        threat_id = "2147817682"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 45 f8 40 3b 75 f8 7e 9a 8b 55 dc 03 55 fc 8a 12 30 da ff 45 fc e9}  //weight: 1, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Gepys_ARA_2147837130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gepys.ARA!MTB"
        threat_id = "2147837130"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 f8 83 c0 01 89 45 f8 8b 4d f8 3b 4d 10 7d 39 8b 55 08 89 55 f4 8b 45 0c 89 45 e8 c7 45 fc 35 dc 07 00 c7 45 fc 35 dc 07 00 8b 4d e8 03 4d f8 0f b6 11 89 55 ec 8b 45 ec 89 45 f0 8b 4d f4 03 4d f8 8a 55 f0 88 11 eb b6}  //weight: 2, accuracy: High
        $x_2_2 = "c:\\Mozilla\\jbvusrj.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Gepys_PABE_2147892658_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Gepys.PABE!MTB"
        threat_id = "2147892658"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Gepys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 81 aa 00 00 31 d2 a3 ?? ?? ?? 00 a1 ?? ?? ?? 00 f7 f1 b9 4e 00 01 00 31 d2 f7 f1 a1 ?? ?? ?? 00 89 15 ?? ?? ?? 00 09 d8 88 d9 05 51 c5 00 00 31 d2 a3 ?? ?? ?? 00 d3 e8 b9 ef ff 00 00 f7 f1 8a 0d ?? ?? ?? 00 89 d8 d3 f8 8b 0d ?? ?? ?? 00 89 15 ?? ?? ?? 00 29 c1 31 d2 89 c8 b9 2d 0b 01 00 f7 f1 b9 d5 0d 01 00 8d 43 ff 89 15 ?? ?? ?? 00 23 05 ?? ?? ?? 00 31 d2 f7 f1 a1 ?? ?? ?? 00 0c 01 0f af c3 8b 0d ?? ?? ?? 00 89 15 ?? ?? ?? 00 29 c1 31 d2 89 c8 b9 6c 0a 01 00 f7 f1 b9 99 0e 01 00 a1 ?? ?? ?? 00 89 15 ?? ?? ?? 00 01 d8 31 d2 f7 f1 a1 ?? ?? ?? 00 e9 13 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

