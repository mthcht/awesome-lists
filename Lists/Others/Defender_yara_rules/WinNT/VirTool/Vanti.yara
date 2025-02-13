rule VirTool_WinNT_Vanti_2147574984_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Vanti"
        threat_id = "2147574984"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Vanti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 08 03 01 00 50 ff d6 8b 55 08 6a 1b 59 b8 c0 03 01 00 8d 7a 38 f3 ab 8d 45 fc c7 42 70 d2 03 01 00 50 6a 00 6a 00 8d 45 f4 6a 22 50 6a 10 52 c7 42 34 c6 02 01 00 ff 15 6c 04 01 00}  //weight: 2, accuracy: High
        $x_2_2 = {8d 45 fc c7 42 70 a0 02 01 00 50 6a 00 6a 00 8d 45 f4 6a 22 50 6a 10 52 c7 42 34 28 04 01 00 ff 15 a4 04 01 00 85 c0 7c 19}  //weight: 2, accuracy: High
        $x_4_3 = {0f 20 c0 89 45 0c 25 ff ff fe ff 0f 22 c0 fa 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 fb 8b 45 0c 0f 22 c0}  //weight: 4, accuracy: High
        $x_1_4 = "\\Device\\MIANYI" wide //weight: 1
        $x_1_5 = "\\DosDevices\\MIANYI" wide //weight: 1
        $x_1_6 = "DosDevices\\XRW005" wide //weight: 1
        $x_1_7 = "Device\\XRW005" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Vanti_2147574984_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Vanti"
        threat_id = "2147574984"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Vanti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 51 51 53 8b 5d 0c 56 57 8b 43 60 89 45 f8 8b 48 0c 81 e9 07 00 22 00 74 4d 83 e9 04 74 2f 83 e9 04 74 1d 83 e9 04 75 6b 60 0f 20 e2 89 55 fc 61 8b 45 f8 8b 4d fc 8b 5d 0c 8b 40 10 89 08 eb 53}  //weight: 10, accuracy: High
        $x_10_2 = {0f 20 c0 89 45 0c 25 ff ff fe ff 0f 22 c0 fa 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 fb 8b 45 0c 0f 22 c0}  //weight: 10, accuracy: High
        $x_1_3 = "\\Device\\COK568" wide //weight: 1
        $x_1_4 = "\\DosDevices\\COK568" wide //weight: 1
        $x_1_5 = "\\Device\\XBBO99" wide //weight: 1
        $x_1_6 = "\\DosDevices\\XBBO99" wide //weight: 1
        $x_1_7 = "\\Device\\VXP005" wide //weight: 1
        $x_1_8 = "\\DosDevices\\VXP005" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Vanti_A_2147574989_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Vanti.gen!A"
        threat_id = "2147574989"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Vanti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {51 53 8b 5d 0c 83 65 fc 00 56 8b 73 60 57 89 75 f8 8b 46 0c 2d 07 00 22 00 74 74 6a 04 59 2b c1 74 54 2b c1 74 43 2b c1}  //weight: 15, accuracy: High
        $x_12_2 = {74 27 2b c1 0f 85 8a 00 00 00 b9 80 00 00 c0 0f 32 a9 00 08 00 00 74 07 c7 45 fc 01 00 00 00 8b 46 08 8b 4d fc 89 08 eb 6b}  //weight: 12, accuracy: High
        $x_8_3 = {8b 4e 08 8b 7e 10 8b 73 3c 0f 20 c0 89 45 0c 25 ff ff fe ff 0f 22 c0 fa 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 fb 8b 45 0c 0f 22 c0 32 d2 8b cb}  //weight: 8, accuracy: High
        $x_12_4 = {ec 08 04 00 00 56 57 b9 00 01 00 00 33 c0 8d bd f8 fb ff ff 6a 01 f3 ab 8b 7d 10 8d 45 f8 ff 77 08 50}  //weight: 12, accuracy: High
        $x_15_5 = {85 c0 59 74 0f 80 3e 00 74 0a 8b 45 08 83 20 00 33 c0 eb 25 ff 75 30 ff 75 2c ff 75 28 ff 75 24 ff 75 20 ff 75 1c ff 75 18 ff 75 14 57 ff 75 0c ff 75 08}  //weight: 15, accuracy: High
        $x_8_6 = {8b 73 60 57 89 75 f4 8b 46 0c 2d 07 00 22 00 0f 84 e0 00 00 00 6a 04 59 2b c1 0f 84}  //weight: 8, accuracy: High
        $x_6_7 = {85 c0 74 45 33 ff 89 75 08 8b 06 85 c0 74 16 01 45 08 ff 75 08 e8}  //weight: 6, accuracy: High
        $x_7_8 = {74 07 03 3e 8b 75 08 eb e4 8b 06 85 db 74 0f 85 c0 74 06 03 c7 01 03 eb 14}  //weight: 7, accuracy: High
        $x_10_9 = {83 23 00 eb 0f 85 c0 74 07 03 c7 01 45 0c eb 04 83 65 0c 00 8b 06 8b de 85 c0 74 04 03 f0 eb 02 33 f6 85 f6 75 9f 5f}  //weight: 10, accuracy: High
        $x_10_10 = {85 c0 74 97 0f b7 4e 44 8b d1 33 c0 8b fb c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 66 c7 03 2e 00 e9 77 ff ff ff}  //weight: 10, accuracy: High
        $x_15_11 = {74 1b 0f b7 4e 3c 8b d1 33 c0 8b fb c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 66 c7 03 2e 00 66 8b 46 44 66 3d 0c 00 77 ad 66 85 c0 74 a8 0f b7 c0 8b 5e 46 50 53}  //weight: 15, accuracy: High
        $x_6_12 = {8b 51 f8 3b d7 76 19 3b d3 73 15 8b 51 fc 3b d7 76 0e 3b d3 73 0a 8b 11 3b d7 76 04 3b d3 72 13}  //weight: 6, accuracy: High
        $x_10_13 = {33 c0 eb 77 8b 5d 08 83 65 08 00 66 83 7e 02 00 8d 04 98 89 45 f8 76 e8 8b 45 fc 83 c0 08 89 45 10 eb 03 8b 45 10 8b 48 04 8b 00 83 e8 0c 03 cf c1 e8 02 50 ff 75 f8 51}  //weight: 10, accuracy: High
        $x_8_14 = {85 c0 75 12 0f b7 46 02 83 45 10 28 ff 45 08 39 45 08 72 d2 eb ad 8b 4d 0c c1 e3 04 2b c3 89 01 2b c7 0f b7 4e 02 51 50 ff 75 fc}  //weight: 8, accuracy: High
        $x_15_15 = {83 c9 ff 33 c0 8d 95 b0 fe ff ff f2 ae f7 d1 2b f9 68 44 64 6b 20 8b f7 8b fa 8b d1 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 8d 95 b0 fe ff ff 83 e1 03 f3 a4 8d bd ac fd ff ff 83 c9 ff f2 ae f7 d1 2b f9 8b f7 8b fa 8b d1 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 be 00 40 00 00 56 50}  //weight: 15, accuracy: High
        $x_10_16 = {85 c0 89 45 28 0f 8c d9 00 00 00 83 65 2c 00 33 c0 39 03 6a 60 8b f3 0f 94 c0 89 45 30 58 39 45 20 0f 86 bd 00 00 00 3b 45 20 0f 83 b4 00 00 00 bf 50 0b 01 00 66 8b 07 66 85 c0 74 29 0f b7 c0 50 8d 87 f8 fd ff ff 50 8d 46 5e 50}  //weight: 10, accuracy: High
        $x_6_17 = {89 75 2c 03 36 83 7d 30 00 75 73 33 c0 39 06 0f 94 c0 89 45 30 8b c6 2b c3 83 c0 60 eb a3 83 7d 30 00 75 47 0f b7 4e 3c 8d 56 5e}  //weight: 6, accuracy: High
        $x_10_18 = {8b d9 33 c0 8b fa c1 e9 02 c7 46 04 10 00 00 00 f3 ab 8b cb 83 e1 03 f3 aa 0f b7 4e 44 8b d9 8d 7e 46 33 c0 c1 e9 02 f3 ab 8b cb 8b 5d 1c 83 e1 03 f3 aa 66 c7 46 46 2e 00 66 c7 02 2e 00 eb a0}  //weight: 10, accuracy: High
        $x_8_19 = {8a 10 8a ca 3a 16 75 1a 3a cb 74 12 8a 50 01 8a ca 3a 56 01 75 0c 40 40 46 46 3a cb 75 e2 33 c0 eb 05 1b c0 83 d8 ff 3b c3 74 10 81 c7 06 01 00 00 81 ff 48 3a 01 00 7c b6 eb 07}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_7_*) and 2 of ($x_6_*))) or
            ((2 of ($x_8_*) and 2 of ($x_6_*))) or
            ((2 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_6_*))) or
            ((3 of ($x_8_*) and 1 of ($x_6_*))) or
            ((3 of ($x_8_*) and 1 of ($x_7_*))) or
            ((4 of ($x_8_*))) or
            ((1 of ($x_10_*) and 3 of ($x_6_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 2 of ($x_6_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 2 of ($x_6_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_6_*))) or
            ((1 of ($x_10_*) and 2 of ($x_8_*) and 1 of ($x_6_*))) or
            ((1 of ($x_10_*) and 2 of ($x_8_*) and 1 of ($x_7_*))) or
            ((1 of ($x_10_*) and 3 of ($x_8_*))) or
            ((2 of ($x_10_*) and 2 of ($x_6_*))) or
            ((2 of ($x_10_*) and 1 of ($x_7_*))) or
            ((2 of ($x_10_*) and 1 of ($x_8_*))) or
            ((3 of ($x_10_*))) or
            ((1 of ($x_12_*) and 3 of ($x_6_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 2 of ($x_6_*))) or
            ((1 of ($x_12_*) and 1 of ($x_8_*) and 2 of ($x_6_*))) or
            ((1 of ($x_12_*) and 1 of ($x_8_*) and 1 of ($x_7_*))) or
            ((1 of ($x_12_*) and 2 of ($x_8_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_6_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_7_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_8_*))) or
            ((1 of ($x_12_*) and 2 of ($x_10_*))) or
            ((2 of ($x_12_*) and 1 of ($x_6_*))) or
            ((2 of ($x_12_*) and 1 of ($x_7_*))) or
            ((2 of ($x_12_*) and 1 of ($x_8_*))) or
            ((2 of ($x_12_*) and 1 of ($x_10_*))) or
            ((1 of ($x_15_*) and 2 of ($x_6_*))) or
            ((1 of ($x_15_*) and 1 of ($x_7_*) and 1 of ($x_6_*))) or
            ((1 of ($x_15_*) and 1 of ($x_8_*) and 1 of ($x_6_*))) or
            ((1 of ($x_15_*) and 1 of ($x_8_*) and 1 of ($x_7_*))) or
            ((1 of ($x_15_*) and 2 of ($x_8_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_6_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_7_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_8_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*))) or
            ((1 of ($x_15_*) and 1 of ($x_12_*))) or
            ((2 of ($x_15_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Vanti_B_2147601753_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Vanti.gen!B"
        threat_id = "2147601753"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Vanti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 5f 72 65 67 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {01 00 00 81 ea 07 00 22 00 0f 84}  //weight: 1, accuracy: High
        $x_1_3 = {74 0f 3c 61 7c 08 3c 7a 7f 04 2c 20 88 01 41 eb eb}  //weight: 1, accuracy: High
        $x_1_4 = {83 45 fc 40 81 c3 0a 02 00 00 81 fb}  //weight: 1, accuracy: High
        $x_2_5 = {8d 4d fc 51 8d 4d fc 6a 00 51 6a 0b a3}  //weight: 2, accuracy: High
        $x_2_6 = {81 7b 20 88 88 88 88 0f 84}  //weight: 2, accuracy: High
        $x_3_7 = {69 c0 1c 01 00 00 83 c0 04 68 44 64 6b 20}  //weight: 3, accuracy: High
        $x_4_8 = {8b 70 1c 8b 48 20 8b 78 24 8b 40 18 83 65 f8 00 03 f3 03 cb 03 fb 85 c0 89 45 f0 76 ?? 89 4d f4 8b 45 0c 89 45 fc 8b 45 f4 8b 10 03 d3}  //weight: 4, accuracy: Low
        $x_4_9 = {89 04 8a ff 45 fc 83 7d fc 2b 72 ?? fb 8b 45 c8 0f 22 c0}  //weight: 4, accuracy: Low
        $x_8_10 = {0f 20 c0 89 45 ?? 25 ff ff fe ff 0f 22 c0 fa c7 43 20 88 88 88 88}  //weight: 8, accuracy: Low
        $x_1_11 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Vanti_C_2147605858_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Vanti.gen!C"
        threat_id = "2147605858"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Vanti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 83 f8 09 89 45 fc 72}  //weight: 1, accuracy: High
        $x_2_2 = {8b 41 3c 57 8b 74 08 78 03 f1 39 55 0c 74 ?? 8b 7e 1c 8b 46 20 8b 5e 24}  //weight: 2, accuracy: Low
        $x_2_3 = {8d 45 fc 50 8d 45 fc 53 50 6a 0b ff 15 ?? ?? 01 00}  //weight: 2, accuracy: Low
        $x_2_4 = {81 7a 20 88 88 88 88}  //weight: 2, accuracy: High
        $x_5_5 = {0f 20 c0 89 45 ?? 25 ff ff fe ff 0f 22 c0 fa}  //weight: 5, accuracy: Low
        $x_2_6 = {c7 47 20 88 88 88 88}  //weight: 2, accuracy: High
        $x_3_7 = {0f 22 c0 6a 01 04 00 fb 8b 45}  //weight: 3, accuracy: Low
        $x_1_8 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_9 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_10 = "\\i386\\rising.sys" ascii //weight: 1
        $x_1_11 = {5c 69 33 38 36 5c 6e 6f 64 33 32 [0-8] 2e 73 79 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Vanti_D_2147617574_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Vanti.gen!D"
        threat_id = "2147617574"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Vanti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "IoGetCurrentProcess" ascii //weight: 10
        $x_1_2 = {ff ff fe ff 8b ?? 0f 22 (c0|c1|c2|c3|c6|c7) fa e8 ?? 00 00 00 ff 15 ?? ?? ?? ?? fb 8b (45|4d|55|5d|75|7d) fc 8b ?? 0f 22 (c0|c1|c2|c3|c6|c7) 0a 00 [0-1] 0f 20 (c0|c1|c2|c3|c6|c7) 8b ?? 89 (45|4d|55|5d|75|7d) fc (25|81 (e1|e2|e3|e6|e7))}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff fe ff 0f 22 (c0|c1|c2|c3|c6|c7) fa e8 ?? 00 00 00 ff 15 ?? ?? ?? ?? fb 8b (45|4d|55|5d|75|7d) fc 0f 22 (c0|c1|c2|c3|c6|c7) 08 00 [0-1] 0f 20 (c0|c1|c2|c3|c6|c7) 89 (45|4d|55|5d|75|7d) fc (25|81 (e1|e2|e3|e6|e7))}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Vanti_E_2147629591_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Vanti.gen!E"
        threat_id = "2147629591"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Vanti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 9d 8f a0 c3}  //weight: 1, accuracy: High
        $x_1_2 = {05 e4 9a ce 14}  //weight: 1, accuracy: High
        $x_2_3 = {68 00 0c 00 00 50 6a 0b ff}  //weight: 2, accuracy: High
        $x_2_4 = {20 32 54 76 98 0f 84 ?? 01 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

