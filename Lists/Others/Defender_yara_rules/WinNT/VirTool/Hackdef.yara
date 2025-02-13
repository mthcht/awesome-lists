rule VirTool_WinNT_Hackdef_A_2147732939_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Hackdef.gen!A"
        threat_id = "2147732939"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Hackdef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\\\.\\HxDefDriver" ascii //weight: 2
        $x_2_2 = "\\\\.\\mailslot\\hxdef-rk100s" ascii //weight: 2
        $x_2_3 = "\\\\.\\mailslot\\hxdef-rk100s0ACEE761" ascii //weight: 2
        $x_2_4 = "Prefetch\\*.pf" ascii //weight: 2
        $x_2_5 = "\\\\.\\mailslot\\hxdef-rkc" ascii //weight: 2
        $x_2_6 = "\\\\.\\mailslot\\hxdef-rkb" ascii //weight: 2
        $x_2_7 = "\\\\.\\mailslot\\hxdef-rks" ascii //weight: 2
        $x_2_8 = "-:INSTALLONLY" ascii //weight: 2
        $x_2_9 = "-:REFRESH" ascii //weight: 2
        $x_2_10 = "-:NOSERVICE" ascii //weight: 2
        $x_2_11 = "-:UNINSTALL" ascii //weight: 2
        $x_2_12 = "-:BD:-" ascii //weight: 2
        $x_2_13 = "GHandles v1.0 for GKit by gray,thx for Holy_Father && Ratter/29A" ascii //weight: 2
        $x_5_14 = "\\DosDevices\\HxDefDriver" wide //weight: 5
        $x_5_15 = "\\Device\\HxDefDriver" wide //weight: 5
        $x_3_16 = "ZwDuplicateToken" ascii //weight: 3
        $x_3_17 = "ZwOpenProcessToken" ascii //weight: 3
        $x_5_18 = {8b 4d e8 89 4d f4 c7 45 f8 00 00 00 00 8d 55 f4 52 8d 45 d0 50 68 ff 0f 1f 20 00 8d 4d a0 51 ff 15}  //weight: 5, accuracy: High
        $x_5_19 = {ff 75 f0 ff 15 f4 07 01 00 85 c0 7c 4d 8d 45 d0 50 6a 01 8d 45 b8 53 50 68 ff 00 0f 00 ff 75 0c ff 15}  //weight: 5, accuracy: High
        $x_5_20 = {85 c0 7c 27 8d 45 d0 6a 08 50 6a 09 ff 75 dc 89 5d d4 ff 15}  //weight: 5, accuracy: High
        $x_5_21 = {85 c0 7c 7a 8d 45 b4 50 68 ff 00 0f 00 8b 4d f0 51 ff 15}  //weight: 5, accuracy: High
        $x_5_22 = {85 c0 7c 30 c7 45 c8 00 00 00 00 6a 08 8d 55 c4 52 6a 09 8b 45 a0 50 ff 15}  //weight: 5, accuracy: High
        $x_5_23 = {85 c0 7c 09 8b 4d b0 c7 01 01 00 00 00 8b 55 c4 52 ff 15}  //weight: 5, accuracy: High
        $x_6_24 = {89 45 e8 8d 45 e8 50 8d 45 b8 50 68 ff 0f 1f 00 8d 45 e4 50 89 55 0c 89 4f 1c c7 45 b8 18 00 00 00 38 39 5d bc 89 5d c0 89 5d c4 89 5d c8 89 5d cc 89 5d ec}  //weight: 6, accuracy: High
        $x_4_25 = {85 c0 7c 4d 8d 45 d0 50 6a 01 53 8d 45 b8 50 68 ff 00 0f 00 ff 75 f0 ff 15}  //weight: 4, accuracy: High
        $x_4_26 = {85 c0 7c 27 6a 08 8d 45 d0 50 6a 09 ff 75 e4 89 5d d4 ff 15}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_2_*))) or
            ((1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_4_*) and 8 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_4_*) and 6 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 8 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*))) or
            ((4 of ($x_5_*))) or
            ((1 of ($x_6_*) and 7 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_6_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Hackdef_C_2147732941_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Hackdef.gen!C"
        threat_id = "2147732941"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Hackdef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 8b 7d 0c 8b 47 60 8b 48 04 89 0d ?? ?? 01 00 8b 40 0c 8b 77 0c 33 db 2d 00 20 22 00 89 9d f0 fb ff ff 0f 84 ?? 01 00 00 6a 04 59 2b c1 74 ?? 89 1e 89 4f 1c c7 [0-5] 10 00 00 c0 e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Hackdef_D_2147732942_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Hackdef.gen!D"
        threat_id = "2147732942"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Hackdef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 50 ff 15 ?? 06 01 00 89 45 f8 c7 45 fc ?? 04 01 00 8b 45 f8 8b 18 89 1d ?? 07 01 00 8b 5d fc 89 18 6a 04 ff 75 f8 ff 15 ?? 06 01 00 8b 45 f4 6a 04 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Hackdef_E_2147732943_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Hackdef.gen!E"
        threat_id = "2147732943"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Hackdef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 20 22 00 89 ?? ?? 0f 84 ?? ?? 00 00 6a 04 59 2b c1 74 ?? 89 ?? 89 ?? 1c c7 45 ?? 10 00 00 c0 e9 ?? 01 00 00 8b 06 8b 56 04 89 ?? 89 45 ?? 8d 45 ?? 50 8d 45 ?? 50 68 ff 0f 1f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Hackdef_F_2147732944_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Hackdef.gen!F"
        threat_id = "2147732944"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Hackdef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 f4 66 89 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c0 0f 8c ?? 00 00 00 8b 85 ?? fb ff ff 66 83 38 05 75 ?? 66 83 78 02 70 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Hackdef_G_2147732945_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Hackdef.gen!G"
        threat_id = "2147732945"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Hackdef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 51 a1 08 0c 01 00 8b 08 89 4d ?? fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b ?? ?? 0d 01 00 a1 24 0c 01 00 8b 48 01 8b 45 fc 8d 0c 88 87 11 89 ?? ?? 0d 01 00 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 33 c0 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_1_2 = "\\Device\\bconusb" wide //weight: 1
        $x_1_3 = "\\DosDevices\\bconusb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Hackdef_H_2147732946_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Hackdef.gen!H"
        threat_id = "2147732946"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Hackdef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 50 ff 15 ?? ?? 01 00 89 45 f8 c7 45 fc dc 05 01 00 8b 45 f8 8b 18 89 1d 28 0a 01 00 8b 5d fc 89 18 6a 04 ff 75 f8 ff 15 ?? ?? 01 00 8b 45 f4 83 c0 04 6a 04 50 8d 45 fc 50 ff d6 83 c4 0c 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Hackdef_I_2147732947_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Hackdef.gen!I"
        threat_id = "2147732947"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Hackdef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d 0c 56 57 8b 43 60 6a 01 5e 89 35 c4 09 01 00 8b 48 04 89 0d c8 09 01 00 89 35 c4 09 01 00 8b 40 0c 89 35 c4 09 01 00 8b 7b 0c 33 c9 2d 00 20 22 00 89 4d f8 89 35 ?? ?? 01 00 0f 84 ?? 01 00 00 6a 04 5a 2b c2 74 ?? 89 0f 89 53 1c c7 45 f8 10 00 00 c0 e9 ?? 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Hackdef_J_2147732948_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Hackdef.gen!J"
        threat_id = "2147732948"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Hackdef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 0c 31 db 8b 47 60 89 5d f4 8b 48 04 89 0d 84 08 01 00 8b 40 0c 8b 77 0c 2d 00 20 22 00 0f 84 ?? 00 00 00 6a 04 59 29 c8 74 ?? 89 1e 89 4f 1c c7 45 f4 10 00 00 c0 e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Hackdef_BJ_2147732950_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Hackdef.BJ"
        threat_id = "2147732950"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Hackdef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 45 78 65 53 61 78 00}  //weight: 10, accuracy: High
        $x_10_2 = {2d 00 20 22 00 0f 84 ?? 00 00 00 6a 04 59 2b c1 74 ?? 89 1e 89 4f 1c c7 45 ?? 10 00 00 c0}  //weight: 10, accuracy: Low
        $x_10_3 = "\\Device\\MSDVDDriver" wide //weight: 10
        $x_10_4 = "\\DosDevices\\MSDVDDriver" wide //weight: 10
        $x_1_5 = "ZwOpenProcess" ascii //weight: 1
        $x_1_6 = "KeAttachProcess" ascii //weight: 1
        $x_1_7 = "ZwSetInformationProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Hackdef_B_2147732951_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Hackdef.gen!B"
        threat_id = "2147732951"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Hackdef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "125"
        strings_accuracy = "High"
    strings:
        $x_22_1 = {89 55 fc 89 4f 1c c7 45 b8 18 00 00 00 89 5d bc 89 5d c0 89 5d c4 89 5d c8 89 5d cc 89 5d ec}  //weight: 22, accuracy: High
        $x_22_2 = {8b 45 fc 89 45 e8 8d 45 e8 50 8d 45 b8 50 68 ff 0f 1f 00 8d 45 f0 50 89 5d ec}  //weight: 22, accuracy: High
        $x_3_3 = "ZwOpenProcess" ascii //weight: 3
        $x_22_4 = {85 c0 7c 6c 8d 45 0c 50 68 ff 00 0f 00 ff 75 f0}  //weight: 22, accuracy: High
        $x_3_5 = "ZwOpenProcessToken" ascii //weight: 3
        $x_22_6 = {7c 4d 8d 45 d0 50 6a 01 53 8d 45 b8 50 68 ff 00 0f 00 ff 75 0c}  //weight: 22, accuracy: High
        $x_3_7 = "ZwDuplicateToken" ascii //weight: 3
        $x_22_8 = {85 c0 7c 27 6a 08 8d 45 d0 50 6a 09 ff 75 dc 89 5d d4}  //weight: 22, accuracy: High
        $x_3_9 = "ZwSetInformationProcess" ascii //weight: 3
        $x_22_10 = {8b 0e 8d 46 04 89 45 fc 8b 00 89 45 d8 8d 45 f8 50 89 1e 51 c7 47 1c 04}  //weight: 22, accuracy: High
        $x_3_11 = "PsLookupProcessByProcessID" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_22_*) and 5 of ($x_3_*))) or
            ((6 of ($x_22_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Hackdef_DA_2147732952_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Hackdef.DA"
        threat_id = "2147732952"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Hackdef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 00 40 00 00 d1 e6 56 6a 00 e8 ?? ?? ?? ?? 85 c0 74 28 89 45 fc 6a 00 56 50 ff 75 08 ff 15 ?? ?? ?? ?? a9 00 00 00 c0 74 16 3d 04 00 00 c0 75 0a ff 75 fc e8 ?? ?? ?? ?? eb ca 6a 00 8f 45 fc 8b 45 fc 5e c9 c2 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 f1 03 00 00 5b b8 00 00 23 fa ba 9e f8 3a 63 bf c1 a3 81 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

