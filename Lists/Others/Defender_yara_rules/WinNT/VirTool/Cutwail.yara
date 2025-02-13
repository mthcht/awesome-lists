rule VirTool_WinNT_Cutwail_B_2147596630_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.gen!B"
        threat_id = "2147596630"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 65 72 76 69 63 65 73 2e 65 78 65 [0-16] 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 [0-16] 73 65 72 76 69 63 65 73 2e 65 78 65 [0-16] 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 [0-16] 73 65 72 76 69 63 65 73 2e 65 78 65 [0-16] 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_5_2 = {8b 5d 10 6a 0d bf [0-4] 8d b3 54 01 00 00 59 33 c0 f3 a6 0f 85 3d 01 00 00 8b 75 0c 81 c6 54 01 00 00 6a 0d bf [0-4] 59 33 c0 f3 a6 0f 84 22 01 00 00 53 e8}  //weight: 5, accuracy: Low
        $x_5_3 = {8d 90 88 00 00 00 8d 8e 88 00 00 00 89 11 89 88 8c 00 00 00 8b 45 10 05 88 00 00 00 89 00 8b 45 10 8d 88 88 00 00 00 89 88 8c 00 00 00 e9 e2 00 00 00}  //weight: 5, accuracy: High
        $x_10_4 = {0f bf 00 3d 93 08 00 00 74 7d 3d 28 0a 00 00 74 67 3d ce 0e 00 00 0f 85 bd 00 00 00 8d 45 08 50 ff 75 08 ff 15 [0-4] 85 c0 0f 8c a8 00 00 00 8b 4d 08 8b 91 8c}  //weight: 10, accuracy: Low
        $x_5_5 = {8b 89 88 00 00 00 b8 88 00 00 00 2b c8 2b d0 8d 82 88 00 00 00 8d 91 88 00 00 00 89 10 89 81 8c 00 00 00 8b 45 08 05 88 00 00 00 89 00 8b 45 08 8d 88 88 00 00 00 89 88 8c 00 00 00 eb 61 8d 45 08 50 ff 75 08}  //weight: 5, accuracy: High
        $x_5_6 = {8b 45 08 8b 88 a4 00 00 00 8b 80 a0 00 00 00 ba a0 00 00 00 2b ca 2b c2 03 ca 8d 90 a0 00 00 00 89 11 89 88 a4 00 00 00 8b 45 08 05 a0 00 00 00 89 00 8b 45 08 8d 88 a0 00 00 00 89 88 a4 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Cutwail_C_2147596632_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.C"
        threat_id = "2147596632"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 18 3d 28 0a 00 00 74 07 3d ce 0e 00 00 75 40 c6 45 ff bf c6 45 fe 57 eb 08 c6 45 ff ba c6 45 fe 84 60 b8}  //weight: 2, accuracy: High
        $x_2_2 = {81 f9 93 08 00 00 b8 f8 00 00 00 74 1a 81 f9 28 0a 00 00 74 0d 81 f9 ce 0e 00}  //weight: 2, accuracy: High
        $x_2_3 = {fa 0f 20 c0 89 45 ?? 25 ff ff fe ff 0f 22 c0}  //weight: 2, accuracy: Low
        $x_1_4 = {66 81 3e 4d 5a 75 0d 8b 46 3c 03 c6 66 81 78 14 e0 00}  //weight: 1, accuracy: High
        $x_1_5 = "ZwQuerySystemInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Cutwail_A_2147596635_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.gen!A"
        threat_id = "2147596635"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "63"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "startdrv.exe" ascii //weight: 3
        $x_3_2 = "ZwOpenFile" ascii //weight: 3
        $x_3_3 = "RtlInitUnicodeString" ascii //weight: 3
        $x_3_4 = "PsLookupProcessByProcessId" ascii //weight: 3
        $x_3_5 = "NtBuildNumber" ascii //weight: 3
        $x_3_6 = "PsSetCreateProcessNotifyRoutine" ascii //weight: 3
        $x_3_7 = "ZwWriteFile" ascii //weight: 3
        $x_3_8 = "ZwCreateFile" ascii //weight: 3
        $x_3_9 = "KeBugCheckEx" ascii //weight: 3
        $x_3_10 = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 3
        $x_3_11 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\runtime2" wide //weight: 3
        $x_5_12 = "runtime2.sy_" wide //weight: 5
        $x_5_13 = "\\SystemRoot\\Temp\\startdrv.exe" wide //weight: 5
        $x_5_14 = "\\Temp\\startdrv.exe" wide //weight: 5
        $x_5_15 = "\\SystemRoot\\system32\\drivers\\runtime2.sys" wide //weight: 5
        $x_5_16 = "\\Device\\Rntm2" wide //weight: 5
        $x_10_17 = {55 8b ec 51 fa 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 8b 0d ?? ?? 01 00 8b 09 a1 ?? 29 01 00 8b 40 01 c7 04 81 ?? 1f 01 00 8b 0d ?? ?? 01 00 8b 09 a1 ?? ?? 01 00 8b 40 01 c7 04 81 ?? 1f 01 00 8b 0d ?? ?? 01 00 8b 09 a1 ?? ?? 01 00 8b 40 01 c7 04 81 ?? 21 01 00 8b 0d ?? ?? 01 00 8b 09 a1 ?? 29 01 00 8b 40 01 c7 04 81 ?? 23 01 00 8b 0d ?? ?? 01 00 a1 ?? ?? 01 00 8b 40 01 8b 09 c7 04 81 ?? 24 01 00 8b 45 fc 0f 22 c0 fb c9 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 11 of ($x_3_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 10 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Cutwail_E_2147598116_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.E"
        threat_id = "2147598116"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 7d ff ff ff 0f b7 c0 83 f8 19 74 28 83 f8 50 74 23 3d e8 03 00 00 72 07 3d b8 0b 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Cutwail_F_2147599189_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.F"
        threat_id = "2147599189"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EXERESOURCE" wide //weight: 1
        $x_1_2 = "\\runtime3" ascii //weight: 1
        $x_1_3 = "\\DosDevices\\Rntm3" wide //weight: 1
        $x_1_4 = "\\Device\\Rntm3" wide //weight: 1
        $x_1_5 = "\\FileSystem" wide //weight: 1
        $x_1_6 = "WLCtrl32.dll" wide //weight: 1
        $x_1_7 = {8b 51 18 83 c2 30 52 e8 ?? ?? ff ff 89 45 f0 83 7d f0 00 74 07 c7 45 f4 22 00 00 c0}  //weight: 1, accuracy: Low
        $x_2_8 = {c6 45 e4 43 c6 45 e5 72 c6 45 e6 65 c6 45 e7 61 c6 45 e8 74 c6 45 e9 65 c6 45 ea 54 c6 45 eb 68 c6 45 ec 72 c6 45 ed 65 c6 45 ee 61 c6 45 ef 64 c6 45 f0 00 e8}  //weight: 2, accuracy: High
        $x_4_9 = {eb ae 8b 85 e8 fc ff ff 50 68 ?? ?? 01 00 8b 4d cc 51 e8 ?? ?? 00 00 83 c4 0c 8d 55 d0 52 ff 15 ?? ?? 01 00 68}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Cutwail_H_2147601813_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.H"
        threat_id = "2147601813"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\WLCtrl32" wide //weight: 1
        $x_1_2 = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\SafeBoot\\Minimal\\" wide //weight: 1
        $x_1_3 = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\SafeBoot\\Network\\" wide //weight: 1
        $x_1_4 = "\\SystemRoot\\system32\\WLCtrl32.dll" wide //weight: 1
        $x_1_5 = "mutantofthefuture" ascii //weight: 1
        $x_1_6 = "WLEventStartShell" wide //weight: 1
        $x_1_7 = "KeDelayExecutionThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Cutwail_C_2147606366_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.gen!C"
        threat_id = "2147606366"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 7d e0 00 24 6c 9d 74 02 eb 16}  //weight: 1, accuracy: High
        $x_1_2 = {81 3a 52 43 50 54 75 02 eb 02 eb dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Cutwail_I_2147606479_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.I"
        threat_id = "2147606479"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {85 c0 74 69 68 ?? ?? 01 00 8b 4d 0c 51 e8 ?? ?? ff ff 0f b6 d0 85 d2 74 54 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 6a 00 e8 ?? ?? 00 00 6a 01 8d 45 f8 50 8d 4d fc 51 e8}  //weight: 3, accuracy: Low
        $x_1_2 = "\\Winlogon\\Notify\\WinNt32" wide //weight: 1
        $x_1_3 = "WLEventStartShell" wide //weight: 1
        $x_1_4 = "\\SystemRoot\\system32\\WinData.cab" wide //weight: 1
        $x_1_5 = "\\DosDevices\\Prot2" wide //weight: 1
        $x_1_6 = "siberia\\protect\\objfre_wxp_x86\\i386\\protect.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Cutwail_J_2147606851_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.J"
        threat_id = "2147606851"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 45 f8 8b 55 0c 52 a1 ?? ?? ?? ?? 8b 4d fc 03 08 51 e8 ?? ?? 00 00 83 c4 08 85 c0 75 04 b0 01 eb 02 32 c0}  //weight: 2, accuracy: Low
        $x_2_2 = {83 7d 08 00 74 63 83 7d 0c 00 74 5d 68 ?? ?? 00 00 8d 8d ?? ?? ff ff 51 8d 95 ?? ?? ff ff 52 e8}  //weight: 2, accuracy: Low
        $x_1_3 = {24 08 9d 74 17 81 7d ?? 40 24 08 9d}  //weight: 1, accuracy: Low
        $x_1_4 = "EXERESOURCE" wide //weight: 1
        $x_1_5 = "\\FileSystem" wide //weight: 1
        $x_1_6 = "WinNt32.dll" wide //weight: 1
        $x_1_7 = "\\DosDevices\\Prot2" wide //weight: 1
        $x_1_8 = "\\Device\\Prot2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Cutwail_K_2147606859_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.K"
        threat_id = "2147606859"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 54 8b 55 08 03 55 fc 0f b6 02 83 f0 ?? 8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 0f b6 42 01 83 f0}  //weight: 2, accuracy: Low
        $x_2_2 = {68 52 57 4e 44 8b 4d e4 51 8b 55 14 52 ff 15 ?? ?? ?? ?? 89 45 f0 83 7d f0 00 74 1b}  //weight: 2, accuracy: Low
        $x_2_3 = {75 05 8b 45 08 eb 1b 8b 45 08 33 d2 f7 75 0c 89 45 fc 8b 45 fc}  //weight: 2, accuracy: High
        $x_2_4 = {73 39 8b 4d fc 81 c1 ?? ?? ?? ?? 89 4d f8 8b 55 f8 81 3a 05 a1 55 f3 75 20}  //weight: 2, accuracy: Low
        $x_2_5 = {7c 1f 8b 55 0c 52 a1 ?? ?? ?? ?? 8b 4d fc 03 08 51 e8 ?? ?? ?? ?? 83 c4 08 85 c0 75 04 c6 45 f7 01}  //weight: 2, accuracy: Low
        $x_2_6 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 50 00 72 00 6f 00 74 00 33 00 00 00}  //weight: 2, accuracy: High
        $x_1_7 = {70 72 6f 74 65 63 74 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_8 = {49 6e 6e 65 72 44 72 76 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_9 = {63 49 60 00 7f 52 62 47 7d 41 73 00 7e 41 7f 4e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Cutwail_D_2147617864_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.gen!D"
        threat_id = "2147617864"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 3d 28 0a 73 09 83 25 ?? ?? ?? ?? 00 eb 0c 75 0a c7 05 ?? ?? ?? ?? 64 01 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {ff 73 fc 8b 03 05 ?? ?? ?? ?? 50 8b 43 f8 03 45 dc 50 e8 ?? ?? ff ff 83 c3 28 ff 45 e0 0f b7 46 06 39 45 e0 7c da}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 46 28 03 45}  //weight: 1, accuracy: High
        $x_1_4 = "hNrtk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Cutwail_E_2147619812_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.gen!E"
        threat_id = "2147619812"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 38 ee dd cc bb 75 0f ff 75 0c ff 75 08}  //weight: 2, accuracy: High
        $x_2_2 = {85 c0 76 0c 80 b1 90 01 05 41 3b c8 72 f4}  //weight: 2, accuracy: High
        $x_1_3 = {83 c1 38 56 8b 55 0c 8b 14 82 8b f1 87 16 40 83 c1 04}  //weight: 1, accuracy: High
        $x_1_4 = "hNrtk" ascii //weight: 1
        $x_1_5 = {74 2f 8b 46 18 83 c0 30 50 e8 ?? ?? ff ff 85 c0 74 1f be 22 00 00 c0}  //weight: 1, accuracy: Low
        $x_1_6 = "ndis_ver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Cutwail_L_2147621443_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.L"
        threat_id = "2147621443"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 05 8b 45 08 eb 1b 8b 45 08 33 d2 f7 75 0c 89 45 fc 8b 45 fc 83 c0 01 89 45 fc 8b 45 fc}  //weight: 2, accuracy: High
        $x_2_2 = {68 52 57 4e 44 8b 45 f8 50 6a 00}  //weight: 2, accuracy: High
        $x_1_3 = {e9 5c ff ff ff 8b 45 fc 8b 4d 0c 89 48 34}  //weight: 1, accuracy: High
        $x_1_4 = {0f 32 89 45 f0 83 7d f0 00 75 ?? 0f 01 4d}  //weight: 1, accuracy: Low
        $x_1_5 = {68 e8 d8 02 9a 68 5d 33 78 df}  //weight: 1, accuracy: High
        $x_1_6 = {0f b6 02 3d ff 00 00 00 75 1c 8b 4d f4 0f b6 51 01 83 fa 25 75 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Cutwail_M_2147626642_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.M"
        threat_id = "2147626642"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 65 00 78 00 65 00 00 00 5c 00 44 00 72 00 69 00 76 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 00 66 3d 28 0a 73 09 83 25 ?? ?? 01 00 00 eb 0c 75 0a c7 05 ?? ?? 01 00 64 01 00 00 a1 ?? ?? 01 00 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 49 28 03 c8 51 56 68 ?? ?? 01 00 56 ff 75 ?? 57 ff 15 ?? ?? ?? ?? 56 56 56 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Cutwail_N_2147628513_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.N"
        threat_id = "2147628513"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Windows" wide //weight: 1
        $x_1_2 = "CSDVersion" wide //weight: 1
        $x_1_3 = "services.exe" wide //weight: 1
        $x_1_4 = "\\SystemRoot\\system32\\drivers\\ntfs.sys" wide //weight: 1
        $x_10_5 = {68 44 4e 57 52 6a 30 6a 00 ff 15 ?? ?? 01 00 8b f0 85 f6 74 26 6a 00 6a 01 57 6a 00 68 ?? ?? 01 00 6a 00 55 56 ff 15 ?? ?? 01 00 6a 00 6a 00 68 45 34 23 12 56 ff 15 ?? ?? 01 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Cutwail_F_2147641131_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Cutwail.gen!F"
        threat_id = "2147641131"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c9 74 0b 31 06 83 c6 04 c1 c0 03 49 eb f1}  //weight: 1, accuracy: High
        $x_1_2 = {c7 80 04 04 00 00 ?? ?? ?? ?? 8b 45 fc 0f 22 c0 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

