rule VirTool_WinNT_Rootkitdrv_A_2147572132_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.A"
        threat_id = "2147572132"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ServiceDescriptorTable" ascii //weight: 1
        $x_1_2 = "services.exe" wide //weight: 1
        $x_1_3 = "KeAttachProcess" ascii //weight: 1
        $x_1_4 = "\\systemroot\\system32\\ntoskrnl.exe" wide //weight: 1
        $x_1_5 = {66 63 6f 6d 69 70 00 00 66 75 63 6f 6d 69 70 00 66 66 72 65 65 70 00 00 66 62 73 74 70}  //weight: 1, accuracy: High
        $x_1_6 = {6b 6d 6f 64 65 78 70 6c 69 62 3a 63 61 6e 6e 6f 74 20 71 75 65 72 79 20 73 79 73 6d 6f 64 20 69 6e 66 6f 20 74 6f 20 67 65 74 20 6d 6f 64 62 61 73 65 21 0a}  //weight: 1, accuracy: High
        $x_1_7 = {25 ff ff fe ff 0f 22 c0 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 8d 04 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_B_2147572273_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!B"
        threat_id = "2147572273"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "[Alarm] WriteMemoey Detected" ascii //weight: 5
        $x_5_2 = "[Alarm] ReadMemoey Detected" ascii //weight: 5
        $x_5_3 = "[Alarm] OpenProcess Detected" ascii //weight: 5
        $x_5_4 = "[Alarm] ProcessScan Detected" ascii //weight: 5
        $x_5_5 = "[Alarm] DebugPort Check Detected" ascii //weight: 5
        $x_5_6 = "[ALARM]No Support OS Version" ascii //weight: 5
        $x_5_7 = "[ALARM] Windows XP" ascii //weight: 5
        $x_5_8 = "[ALARM] Windows 2000" ascii //weight: 5
        $x_5_9 = "[Alarm] HookSetup" ascii //weight: 5
        $x_5_10 = "[Alarm] HookUnsetup" ascii //weight: 5
        $x_5_11 = "Enemy Process was terminated" ascii //weight: 5
        $x_5_12 = ":::::::Game Resistance Driver:::::::" ascii //weight: 5
        $x_2_13 = "Out Process was terminated" ascii //weight: 2
        $x_5_14 = "ZwWriteVirtualMemory Hook Unsetup" ascii //weight: 5
        $x_5_15 = "ZwWriteVirtualMemory Hook Setup" ascii //weight: 5
        $x_5_16 = "ZwReadVirtualMemory Hook Unsetup" ascii //weight: 5
        $x_5_17 = "ZwReadVirtualMemory Hook Setup" ascii //weight: 5
        $x_5_18 = "ZwQuerySystemInformation Hook Unsetup" ascii //weight: 5
        $x_5_19 = "ZwQuerySystemInformation Hook Setup" ascii //weight: 5
        $x_5_20 = "ZwOpenThread Hook Unsetup" ascii //weight: 5
        $x_5_21 = "ZwOpenThread Hook Setup" ascii //weight: 5
        $x_2_22 = "\\DosDevices\\GR" wide //weight: 2
        $x_5_23 = "\\DosDevices\\c:\\antiprevent.ini" wide //weight: 5
        $x_5_24 = "\\DosDevices\\c:\\antiprevent2.ini" wide //weight: 5
        $x_2_25 = "\\Device\\GR" wide //weight: 2
        $x_10_26 = {c7 44 24 60 18 00 00 00 89 74 24 64 c7 44 24 6c 40 00 00 00 89 4c 24 68 89 74 24 70 89 74 24 74 ff 15}  //weight: 10, accuracy: High
        $x_10_27 = {68 e0 40 01 00 52 56 56 56 50 ff 15}  //weight: 10, accuracy: High
        $x_1_28 = {c7 05 24 41 01 00 a0 00 00}  //weight: 1, accuracy: High
        $x_1_29 = {c7 05 0c 41 01 00 9c 00 00}  //weight: 1, accuracy: High
        $x_1_30 = {c7 05 20 41 01 00 28 01 00}  //weight: 1, accuracy: High
        $x_1_31 = {c7 05 20 41 01 00 c4 00 00}  //weight: 1, accuracy: High
        $x_1_32 = {c7 05 00 41 01 00 a4 01 00}  //weight: 1, accuracy: High
        $x_1_33 = {c7 05 08 41 01 00 e4 01 00}  //weight: 1, accuracy: High
        $x_1_34 = {c7 05 0c 41 01 00 84 00 00}  //weight: 1, accuracy: High
        $x_1_35 = {c7 05 24 41 01 00 88 00 00}  //weight: 1, accuracy: High
        $x_1_36 = {c7 05 00 41 01 00 b0 01 00}  //weight: 1, accuracy: High
        $x_5_37 = {8d 4c 24 6c 68 08 40 01 00 51 ff d3 8b 2d 1c 30 01 00 8d 54 24 6c 6a 01 8d 44 24 20 52 50 ff d5 56 56 6a 20 6a 03 56 68 80}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((8 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((8 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((8 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((9 of ($x_5_*) and 5 of ($x_1_*))) or
            ((9 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((9 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((9 of ($x_5_*) and 3 of ($x_2_*))) or
            ((10 of ($x_5_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 8 of ($x_5_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*) and 6 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_AI_2147575497_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.AI"
        threat_id = "2147575497"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {30 04 16 80 7d 10 00 74 09 8d 45 08 50 e8}  //weight: 5, accuracy: High
        $x_5_2 = {8b 7d 0c 0f b6 44 3a ff 89 45 08 8d 45 08 50 e8}  //weight: 5, accuracy: High
        $x_3_3 = "KeNumberProcessors" ascii //weight: 3
        $x_3_4 = "KeGetCurrentIrql" ascii //weight: 3
        $x_1_5 = {5c 00 3f 00 3f 00 5c 00 00 00 5c 00 3f 00 3f 00 5c 00 50 00 48 00 59 00 53 00 49 00 43 00 41 00 4c 00 44 00 52 00 49 00 56 00 45}  //weight: 1, accuracy: High
        $x_1_6 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 77 00 69 00 6e 00 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_CL_2147595038_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.CL"
        threat_id = "2147595038"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 00 73 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 00 00 00 00 65 78 70}  //weight: 2, accuracy: High
        $x_1_2 = {6a 04 8d 45 fc 50 6a 0b ff d6 3d 04 00 00 c0 75 2d 68 44 64 6b 20}  //weight: 1, accuracy: High
        $x_1_3 = {74 4a 8b 47 3c 8b 44 38 78 83 65 08 00 03 c7 8b 48 18}  //weight: 1, accuracy: High
        $x_1_4 = {83 c0 14 89 01 66 81 38 0b 01 75 10 8b 4c 24 10 05 e0 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_CM_2147595140_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.CM"
        threat_id = "2147595140"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 41 01 8b 0d ?? ?? 01 00 8b 09 c7 04 81}  //weight: 2, accuracy: Low
        $x_1_2 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_3 = {53 79 73 74 65 6d 00 56 57 ff 15}  //weight: 1, accuracy: High
        $x_2_4 = {0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 5f 5e 5b c3 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_CO_2147595148_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.CO"
        threat_id = "2147595148"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KeServiceDescriptorTable" ascii //weight: 2
        $x_2_2 = "MsMgr Driver for Proctect" wide //weight: 2
        $x_1_3 = {68 53 59 53 48 ff 70 08 6a 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 48 41 53 48 68 34 04 00 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_5 = {74 21 8a 11 80 fa 2a 74 1a 3c 61 7c 06}  //weight: 1, accuracy: High
        $x_1_6 = {68 48 4f 4f 4b 50 6a 00 89 45 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_CQ_2147595181_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.CQ"
        threat_id = "2147595181"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b7 00 3d 93 08 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {74 66 3d 28 0a 00 00 74 35 3d ce 0e 00 00 74 04 32 c0}  //weight: 2, accuracy: High
        $x_2_3 = {fa 0f 20 c0 89 44 24 00 25 ff ff fe ff 0f 22 c0 8b 01}  //weight: 2, accuracy: High
        $x_2_4 = {66 83 38 21 75 05 66 c7 00 5c 00}  //weight: 2, accuracy: High
        $x_1_5 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_6 = "NtBuildNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_BS_2147603507_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.BS"
        threat_id = "2147603507"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 89 45 c8 ff 36 53 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 0c fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 8b 4d c8 89 04 99 0f 20 c0 0d 00 00 01 00 0f 22 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {83 65 fc 00 6a 04 6a 04 53 ff 15 ?? ?? ?? ?? 6a 04 6a 04 56 ff 15 ?? ?? ?? ?? 83 4d fc ff 8b 1b a1 ?? ?? ?? ?? 39 58 08 77 09 c7 45 d0 0d 00 00 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_BT_2147605078_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.BT"
        threat_id = "2147605078"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8d 77 04 56 ff d3 84 c0 74 32 b1 1f ff 15 ?? ?? ?? ?? 8a c8 0f 20 c0 25 ff ff fe ff 0f 22 c0 c7 07 ?? ?? 00 00 c7 06 ?? ?? ?? ?? 0f 20 c0 0d 00 00 01 00 0f 22 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 03 0f be c0 88 04 0a 41 4e 75 e4 80 7d 08 2e 5e 75 16 80 7d 09 73 75 10 80 7d 0a 79 75 0a 80 7d 0b 73 75 04 b0 01 eb 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_BU_2147605086_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.BU"
        threat_id = "2147605086"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 7e 38 f3 ab b8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 46 48 89 46 44 c7 46 70 ?? ?? ?? ?? c7 46 34 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 53 53 8d 45 f8 50 8d 45 fc 50}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 0c 98 00 00 00 c7 45 fc 88 00 00 00 eb 1e c7 45 0c a0 00 00 00 c7 45 fc fc 01 00 00 eb 0e c7 45 0c 88 00 00 00 c7 45 fc 74 01 00 00 8b 45 0c 8d 0c 30 39 09 89 4d f8 74 56 8b d1 2b 55 0c 33 c0 8d 7d e4 ab ab ab ab aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_I_2147605501_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.I"
        threat_id = "2147605501"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 e4 8b c0 81 f9 4b e1 22 00 74 0a ?? bb 00 00 c0 e9 ?? ?? 00 00 83 65 fc 00 6a 04 6a 04 53 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {39 48 08 77 07 ?? 0d 00 00 c0 eb ?? 8b 00 8b 14 88 8b ?? 8b ?? ?? ?? 01 00 3b ?? 01 75}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 dc e9 2b c2 83 e8 05 89 45 dd 6a 05 52 8d 45 dc 50 e8}  //weight: 1, accuracy: High
        $x_1_4 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_W_2147608035_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.W"
        threat_id = "2147608035"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 25 8b 4d ?? 8b 14 8d ?? ?? ?? ?? 8b 45 ?? 8a 0c 02 80 f1 ?? 8b 55 ?? 8b 04 95 ?? ?? ?? ?? 8b 55 ?? 88 0c 10}  //weight: 10, accuracy: Low
        $x_10_2 = "\\Device\\dpti" wide //weight: 10
        $x_10_3 = "\\Device\\IPFILTERDRIVER" wide //weight: 10
        $x_1_4 = {00 64 72 77 65 62 2e 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 61 67 6e 6d 69 74 75 6d 2e 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 73 79 6d 61 6e 74 65 63 2e 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 6b 61 73 70 65 72 73 6b 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_AR_2147609573_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.AR"
        threat_id = "2147609573"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "130"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {83 26 00 83 66 04 00 2d ?? ?? ?? ?? 74 56 83 e8 04 74 0b c7 06 10 00 00 c0}  //weight: 100, accuracy: Low
        $x_10_2 = "\\Device\\Nessery" wide //weight: 10
        $x_10_3 = "\\DosDevices\\Nessery" wide //weight: 10
        $x_10_4 = "\\Sys\\exe\\i386\\msdirectx.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_AS_2147609574_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.AS"
        threat_id = "2147609574"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "130"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {c7 45 fc 00 00 00 00 eb ?? 8b 45 fc 83 c0 01 89 45 fc 81 7d fc 00 10 00 00 73 ?? 6a 06 8b 4d 08 03 4d fc 51 68}  //weight: 100, accuracy: Low
        $x_10_2 = "\\JCC_WORK\\CurrentWorking\\rootkit\\phvxd\\Release\\phvxd.pdb" ascii //weight: 10
        $x_10_3 = "\\Device\\phvxd" wide //weight: 10
        $x_10_4 = "\\DosDevices\\phvxd" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_AT_2147609836_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.AT"
        threat_id = "2147609836"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\Device\\SafeNTKernel" wide //weight: 10
        $x_10_2 = "\\SystemRoot\\System32\\ntkrnlpa.exe" wide //weight: 10
        $x_10_3 = "\\driver\\bypass\\bypass\\i386\\bypass.pdb" ascii //weight: 10
        $x_1_4 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_5 = {68 6e 45 54 74 8b 45 ?? c1 e0 02 50 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_6 = {fa 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 a1 ?? ?? ?? ?? 8b 00 8b 15}  //weight: 1, accuracy: Low
        $x_1_7 = {fa 0f 20 c0 89 45 ?? 25 ff ff fe ff 0f 22 c0 a1 ?? ?? ?? ?? 8b 40 01 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_AU_2147609841_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.AU"
        threat_id = "2147609841"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "/c del %s > nul" ascii //weight: 10
        $x_10_2 = {4e 65 74 42 6f 74 5c 69 33 38 36 5c [0-8] 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_10_3 = "Microsoft Corporation" wide //weight: 10
        $x_10_4 = "KeServiceDescriptorTable" ascii //weight: 10
        $x_10_5 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_1_6 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 07 8b 4d ?? 89 04 8b 0f 20 c0 0d 00 00 01 00 0f 22 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_AV_2147609843_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.AV"
        threat_id = "2147609843"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\Device\\SNAKEMON" wide //weight: 10
        $x_10_2 = {5c 64 6f 77 6e 6c 6f 61 64 65 72 5c 73 79 73 5c 69 33 38 36 5c [0-8] 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_1_3 = "KeAddSystemServiceTable" wide //weight: 1
        $x_1_4 = "PsLookupThreadByThreadId" wide //weight: 1
        $x_1_5 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 b8 ?? ?? ?? 00 39 30 74 ?? 83 c0 04 3d}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 40 01 8b 12 c7 04 82 ?? ?? ?? 00 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: Low
        $x_1_7 = {bb 49 66 73 20 53 ff 75 ?? 6a 01 ff d6 8b f8 85 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_AW_2147609844_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.AW"
        threat_id = "2147609844"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\Device\\SysDrver" wide //weight: 10
        $x_10_2 = "\\objfre_wnet_x86\\i386\\SysDrver.pdb" ascii //weight: 10
        $x_1_3 = {89 14 81 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: High
        $x_1_4 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 83 3d ?? ?? ?? 00 00 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_AX_2147609846_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.AX"
        threat_id = "2147609846"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ntoskrnl.exe" ascii //weight: 1
        $x_1_2 = "\\Device\\sqlodbc" wide //weight: 1
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_4 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 15 00 20 40 00 8b 49 01 8b 02 c7 04 88 10 11 40 00 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: High
        $x_1_5 = {b8 cd cc cc cc be 00 00 00 00 f7 65 04 8b da 89 74 24 5c c1 eb 04 0f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_AY_2147609859_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.AY"
        threat_id = "2147609859"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\Device\\Rntm2" wide //weight: 10
        $x_10_2 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\runtime2" wide //weight: 10
        $x_10_3 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 c3 8b 44 24 04 25 00 f0 ff ff 66 81 38 4d 5a 75 ?? 8b 48 3c 81 3c 08 50 45 00 00 74}  //weight: 10, accuracy: Low
        $x_1_4 = "KeDelayExecutionThread" ascii //weight: 1
        $x_1_5 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_6 = "ZwQuerySystemInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_AZ_2147609866_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.AZ"
        threat_id = "2147609866"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\Device\\xprtect" wide //weight: 10
        $x_10_2 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 42 01 8b 15 ?? ?? ?? 00 8b 12 c7 04 82 10 10 01 00}  //weight: 10, accuracy: Low
        $x_1_3 = "{AAED18BE6069-4E97-84F6-D65A8C4BCD99}" ascii //weight: 1
        $x_1_4 = "{BB0D62A63DCF-4DE7-8952-44D1B2D3AA8F}" ascii //weight: 1
        $x_1_5 = "{A3F23EF2D946-4D4F-978A-9FF5A0026EA4}" ascii //weight: 1
        $x_1_6 = "{AAF23EF2D946-4D4F-978A-9FF5A0026EA4}" ascii //weight: 1
        $x_1_7 = "{3366EF96-28E5-49EE-99BF-7F20C99CC5EE}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_BW_2147609971_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.BW"
        threat_id = "2147609971"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "KeTickCount" ascii //weight: 10
        $x_10_2 = "\\crazy\\sources\\chmod\\objchk_wxp_x86\\i386\\w" ascii //weight: 10
        $x_10_3 = {c1 e8 08 33 02 25 ff ff 00 00 a3 04 1e 01 00 75 ?? 8b c1 a3 ?? ?? ?? ?? f7 d0}  //weight: 10, accuracy: Low
        $x_1_4 = "\\Device\\HarddiskVolume1\\Program Files\\Scpad\\.dll" wide //weight: 1
        $x_1_5 = "\\Device\\HarddiskVolume1\\Arquivos de Programas\\Scpad\\.dll" wide //weight: 1
        $x_1_6 = "\\Device\\HarddiskVolume1\\Arquivos de Programas\\GbPlugin\\.gpc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_KC_2147610109_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KC"
        threat_id = "2147610109"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeSetEvent" ascii //weight: 1
        $x_1_2 = "OiWxegoExxeglTvsgiww" ascii //weight: 1
        $x_1_3 = "explorer.exe" ascii //weight: 1
        $x_1_4 = "OiMrmxmepmdiEtg" ascii //weight: 1
        $x_1_5 = "ZwWriteFile" ascii //weight: 1
        $x_1_6 = "ntoskrnl.exe" ascii //weight: 1
        $x_1_7 = "\\DosDevices\\" ascii //weight: 1
        $x_1_8 = "ibtpsviv.ibi" ascii //weight: 1
        $x_1_9 = "msdn32.tlf" ascii //weight: 1
        $x_1_10 = "qwhr76.xpj" ascii //weight: 1
        $x_1_11 = "rxovrpte.ibi" ascii //weight: 1
        $x_1_12 = "\\system32" ascii //weight: 1
        $x_1_13 = "ntkrnlpa.exe" ascii //weight: 1
        $x_1_14 = "IoCreateDevice" ascii //weight: 1
        $x_1_15 = "OiYrwxegoHixeglTvsgiww" ascii //weight: 1
        $x_1_16 = "QqQetPsgoihTekiwWtigmjcGegli" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_BX_2147610114_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.BX"
        threat_id = "2147610114"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 0d 00 00 c0 eb ?? 8b 08 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 03 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Device\\RESSDT" wide //weight: 1
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_4 = "\\code\\RESSDT\\i386\\RESSDT.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_BY_2147610116_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.BY"
        threat_id = "2147610116"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\i386\\lanmandrv.pdb" ascii //weight: 1
        $x_1_2 = "\\DosDevices\\LanManDrv" wide //weight: 1
        $x_1_3 = "KeServiceDescriptorTable" wide //weight: 1
        $x_1_4 = "MmGetSystemRoutineAddress" ascii //weight: 1
        $x_1_5 = {68 30 63 70 70 ff 75 ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_6 = {fa 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 83 7d 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KD_2147610167_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KD"
        threat_id = "2147610167"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ntoskrnl.exe" ascii //weight: 1
        $x_1_2 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_4 = "KeInitializeEvent" ascii //weight: 1
        $x_1_5 = "IoCreateDevice" ascii //weight: 1
        $x_1_6 = "ZwOpenKey" ascii //weight: 1
        $x_1_7 = "PsLookupProcessByProcessId" ascii //weight: 1
        $x_1_8 = "KeWaitForSingleObject" ascii //weight: 1
        $x_1_9 = "PsCreateSystemThread" ascii //weight: 1
        $x_1_10 = "KeSetEvent" ascii //weight: 1
        $x_1_11 = "IofCompleteRequest" ascii //weight: 1
        $x_1_12 = "ZwCreateFile" ascii //weight: 1
        $x_1_13 = "ObQueryNameString" ascii //weight: 1
        $x_1_14 = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" wide //weight: 1
        $x_1_15 = "{24531025-29F0-8812-FG8H-F512219090H1}" ascii //weight: 1
        $x_1_16 = "{5D42434E-BCA3-4061-9FAC-C3ABEE0B82EC}" ascii //weight: 1
        $x_1_17 = "\\Device\\{5D42434E-BCA3-4061-9FAC-C3ABEE0B82EC}" wide //weight: 1
        $x_1_18 = "\\DosDevices\\{5D42434E-BCA3-4061-9FAC-C3ABEE0B82EC}" wide //weight: 1
        $x_1_19 = "ibtpsviv.ibi" ascii //weight: 1
        $x_1_20 = "rxovrpte.ibi" ascii //weight: 1
        $x_1_21 = "qwhr76.xpj" ascii //weight: 1
        $x_1_22 = "OiMrmxmepmdiEtg" ascii //weight: 1
        $x_1_23 = "QqQetPsgoihTekiwWtigmjcGegli" ascii //weight: 1
        $x_1_24 = "OiYrwxegoHixeglTvsgiww" ascii //weight: 1
        $x_1_25 = "OiWxegoExxeglTvsgiww" ascii //weight: 1
        $x_1_26 = "OiMrwivxUyiyiEtg" ascii //weight: 1
        $x_1_27 = "Get_Cur_Image_Path is %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_BZ_2147610193_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.BZ"
        threat_id = "2147610193"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e8 08 33 02 25 ff ff 00 00 a3 ?? ?? ?? ?? 75 07 8b c1 a3 ?? ?? ?? ?? f7 d0 a3 ?? ?? ?? ?? 5d e9}  //weight: 10, accuracy: Low
        $x_10_2 = "ZwQueryDirectoryFile" ascii //weight: 10
        $x_10_3 = "ZwQuerySystemInformation" ascii //weight: 10
        $x_10_4 = "KeServiceDescriptorTable" ascii //weight: 10
        $x_1_5 = "hide" ascii //weight: 1
        $x_1_6 = "root" ascii //weight: 1
        $x_1_7 = "Undead" ascii //weight: 1
        $x_1_8 = "rootkit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_CW_2147610212_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.CW"
        threat_id = "2147610212"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 0c 90 90 0f 20 c0 0d 00 00 01 00 0f 22 c0 c7 45 fc ff ff ff ff eb}  //weight: 10, accuracy: High
        $x_10_2 = "\\SystemRoot\\system32\\ntkrnlpa.exe" wide //weight: 10
        $x_1_3 = "GetSystemDirectoryW" ascii //weight: 1
        $x_1_4 = "PsCreateSystemThread" ascii //weight: 1
        $x_1_5 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_6 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_CX_2147610239_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.CX"
        threat_id = "2147610239"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 0c 81 ff d6 0f 20 c0 0d 00 00 01 00 0f 22 c0 83 25 ?? ?? ?? ?? 00 33 c0 40 5e}  //weight: 10, accuracy: Low
        $x_10_2 = "NetWorks.sys" wide //weight: 10
        $x_10_3 = "\\Device\\NetSetup" wide //weight: 10
        $x_1_4 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_5 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_CY_2147610251_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.CY"
        threat_id = "2147610251"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 8b 4d e0 89 04 99 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 10, accuracy: High
        $x_10_2 = "KeServiceDescriptorTable" ascii //weight: 10
        $x_1_3 = "\\AntiDriver.pdb" ascii //weight: 1
        $x_1_4 = "\\XNG_AntiVersion" ascii //weight: 1
        $x_1_5 = "\\Device\\XNGAnti" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_CZ_2147610255_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.CZ"
        threat_id = "2147610255"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 8b ff 55 8b 75 ?? 81 78 04 ec 5d ff 25 75 ?? 8b 48 08 89 4d ?? 8b 09}  //weight: 1, accuracy: Low
        $x_1_2 = "CLASSPNP.SYS" ascii //weight: 1
        $x_1_3 = "\\Device\\Harddisk0\\DR0" ascii //weight: 1
        $x_1_4 = "MmGetSystemRoutineAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_DE_2147610262_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.DE"
        threat_id = "2147610262"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "133"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 60 8b ?? ?? ?? ?? 00 66 b8 e9 00 66 89 07}  //weight: 100, accuracy: Low
        $x_10_2 = "HookSys" wide //weight: 10
        $x_10_3 = "ntkrnlpa.exe" wide //weight: 10
        $x_10_4 = "\\winddk\\src\\hookint" ascii //weight: 10
        $x_2_5 = "GameMon" ascii //weight: 2
        $x_1_6 = "ZWSHUTDOWNSYSTEM" ascii //weight: 1
        $x_1_7 = "NtAcceptConnectPort" ascii //weight: 1
        $x_1_8 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_DF_2147610267_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.DF"
        threat_id = "2147610267"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "121"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {80 38 4d 75 ?? 80 78 01 5a 75 ?? 89 45 d8 8b 48 3c 03 c8 89 4d d4 74 08 81 39 50 45 00 00}  //weight: 100, accuracy: Low
        $x_10_2 = "port to hide" ascii //weight: 10
        $x_10_3 = "\\HideDriver.pdb" ascii //weight: 10
        $x_10_4 = "HookZwDeviceIoControlFile" ascii //weight: 10
        $x_1_5 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_6 = "KeAddSystemServiceTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_DI_2147610339_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.DI"
        threat_id = "2147610339"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 8b ?? ?? 89 04 99 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 10, accuracy: Low
        $x_2_2 = "\\FUCKXSSDT" wide //weight: 2
        $x_2_3 = "Fuck DisPatch" ascii //weight: 2
        $x_1_4 = "Make Hexie China!" ascii //weight: 1
        $x_1_5 = "What Can You Do?" ascii //weight: 1
        $x_1_6 = "\\Device\\SNSSDT" wide //weight: 1
        $x_1_7 = "\\RESSDT\\i386\\RESSDT.pdb" ascii //weight: 1
        $x_1_8 = "Microsoft Corporation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_DJ_2147610340_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.DJ"
        threat_id = "2147610340"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "winhelp32.exe" ascii //weight: 10
        $x_10_2 = "\\i386\\VIDEO.pdb" ascii //weight: 10
        $x_10_3 = "\\SystemRoot\\system32\\webmin\\VIDEO.sys" wide //weight: 10
        $x_1_4 = "ZwQueryDirectoryFile" ascii //weight: 1
        $x_1_5 = "PsTerminateSystemThread" ascii //weight: 1
        $x_1_6 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_7 = "PsLookupProcessByProcessId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_DL_2147610370_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.DL"
        threat_id = "2147610370"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 4d ?? 8b 55 ?? 8b 45 ?? 8b 00 89 04 8a 0f 20 c0 0d 00 00 01 00 0f 22 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "\\1\\i386\\RESSDT.pdb" ascii //weight: 1
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_DN_2147610463_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.DN"
        threat_id = "2147610463"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "AppInit_DLLs" wide //weight: 10
        $x_10_2 = "ZwQueryInformationFile" ascii //weight: 10
        $x_10_3 = "NDIS_BUFFER_TO_SPAN_PAGES" ascii //weight: 10
        $x_10_4 = "\\SystemRoot\\System32\\user32.dll" wide //weight: 10
        $x_10_5 = "EnforceWriteProtection" wide //weight: 10
        $x_1_6 = {80 7a 01 ff 75 06 80 7a 02 25 74 05}  //weight: 1, accuracy: High
        $x_1_7 = {80 3c 3b e9 75 ?? 8b 44 3b 01 8d 74 38 05 80 3e e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FB_2147616869_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FB"
        threat_id = "2147616869"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 c0 01 00 00 00 83 65 fc 00 6a 04 6a 04 52 ff 15 3c 05 01 00 6a 04 6a 04 56 ff 15 38 05 01 00 83 4d fc ff eb 22}  //weight: 1, accuracy: High
        $x_1_2 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 8b 4d c8 89 04 b9 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 33 ff eb 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FC_2147616870_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FC"
        threat_id = "2147616870"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 08 8b 4d f8 3b 08 73 39 8b 55 f8 8b 45 08 83 7c 90 04 00 74 2a 8b 4d f8 8b 55 fc 8b 45 f8 8b 75 08 8b 0c 8a 3b 4c 86 04 74 15 8b 55 f8 8b 45 08 8b 4c 90 04 8b 55 f8 8b 45 fc 8d 14 90 87 0a}  //weight: 10, accuracy: High
        $x_1_2 = "\\Device\\fsodhfn2m" wide //weight: 1
        $x_1_3 = "\\DosDevices\\fsodhfn2m" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_FD_2147616871_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FD"
        threat_id = "2147616871"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 08 80 38 b8 74 04 32 c0 eb 0b 8b 40 01 8b 4c 24 0c 89 01 b0 01}  //weight: 1, accuracy: High
        $x_1_2 = {e8 83 ff ff ff 8b 45 e4 8b 4d 08 89 48 04 8b 02 8b 4d e4 89 41 08 8b 45 0c 89 02 8b 45 e4 c6 00 01 8b 4d e4 e8 53 ff ff ff b0 01 88 45 df eb 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FE_2147616872_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FE"
        threat_id = "2147616872"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 01 0c 00 00 bb 00 60 01 00 05 fd d4 5a 6e 31 03 83 eb fc 49 21 c9 75 f1 61 8d 64 24 fc c7 04 24 00 60 01 00 83 c4 04 ff 64 24 fc}  //weight: 1, accuracy: High
        $x_1_2 = {35 98 96 95 29 d3 c0 05 f6 20 89 95 83 c1 ff 83 f9 00 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FF_2147616873_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FF"
        threat_id = "2147616873"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 7d e0 4b e1 22 00 0f 85 ?? 00 00 00 c7 45 c0 01 00 00 00 83 65 fc 00}  //weight: 10, accuracy: Low
        $x_10_2 = {3b 78 08 73 ?? 8b 00 89 45 c8}  //weight: 10, accuracy: Low
        $x_10_3 = {8b 06 8b 4d c8 89 04 b9 0f 20 c0 0d 00 00 01 00 0f 22 c0}  //weight: 10, accuracy: High
        $x_1_4 = "\\DeViCe\\DarkShell" wide //weight: 1
        $x_1_5 = "\\??\\DarkShell2008" wide //weight: 1
        $x_1_6 = "\\??\\Dark2008" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_FG_2147616876_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FG"
        threat_id = "2147616876"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 c8 00 04 00 00 c7 45 cc 00 00 00 00 c7 45 d0 00 02 00 00 c7 45 d4 00 01 00 00 c7 45 d8 01 01 00 00 b9 05 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 08 50 ff 15 ?? ?? ?? ?? 89 45 f8 81 7d 1c 03 00 12 00 74 08 8b 45 f8 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FH_2147616877_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FH"
        threat_id = "2147616877"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 8b ce c1 e9 02 b8 90 90 90 90 8b fa f3 ab 8b ce 8b 75 08 83 e1 03 f3 aa}  //weight: 1, accuracy: High
        $x_1_2 = {8d 88 04 02 00 00 8b 11 3b d3 74 0c 8b b0 08 02 00 00 89 b2 08 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FI_2147616878_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FI"
        threat_id = "2147616878"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 c2 03 32 10 40 80 38 00 75 f5 8b c2 5a c9 c2 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {89 95 fc fc ff ff c7 45 fc fe ff ff ff 89 95 ec fc ff ff 89 95 f0 fc ff ff 8d 8a 00 00 10 00 89 8d e8 fc ff ff c7 85 18 fd ff ff 07 00 01 00 89 9d a4 fd ff ff c7 85 a8 fd ff ff 3b 00 00 00 6a 23 58 89 85 ac fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FJ_2147616879_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FJ"
        threat_id = "2147616879"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 04 8d 1d ?? ?? ?? ?? 2b d8 83 eb 05 c6 00 e8 89 58 01 9d 61 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 aa aa aa aa a1 ?? ?? ?? ?? c7 40 04 bb bb bb bb 6a 00 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_3 = "System32\\drivers\\ak922.sys" wide //weight: 1
        $x_1_4 = "Services\\AzyKit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FK_2147616880_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FK"
        threat_id = "2147616880"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 83 e8 05 2d ?? ?? ?? ?? 03 45 08 89 45 fc 8b 45 fc 8b e5 5d c2 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 58 83 c0 05 c3}  //weight: 1, accuracy: High
        $x_1_3 = {e8 00 00 00 00 58 83 e8 05 89 45 d8 8b 45 d8 2d b7 14 00 00 89 45 e4 8b 4d fc 2b 4d e4 83 c1 34 89 4d e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FL_2147616881_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FL"
        threat_id = "2147616881"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8b 4d f8 3b 08 73 39 8b 55 f8 8b 45 08 83 7c 90 04 00 74 2a 8b 4d f8 8b 55 fc 8b 45 f8 8b 75 08 8b 0c 8a 3b 4c 86 04 74 15 8b 55 f8 8b 45 08 8b 4c 90 04 8b 55 f8 8b 45 fc 8d 14 90 87 0a}  //weight: 1, accuracy: High
        $x_1_2 = "\\Device\\dmeo8" wide //weight: 1
        $x_1_3 = "\\DosDevices\\dmeo8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FM_2147616882_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FM"
        threat_id = "2147616882"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {ff d6 83 4d ec ff 68 ?? ?? ?? ?? 8d 85 8c fe ff ff 68 b8 04 01 00 50 c7 45 e8 80 3c 36 fe ff 15 ?? ?? ?? ?? 83 c4 0c 8d 85 8c fe ff ff 50 8d 45 a0 50 ff 15 ?? ?? ?? ?? 6a 01}  //weight: 100, accuracy: Low
        $x_10_2 = "222.88.90.22" ascii //weight: 10
        $x_10_3 = "\\SystemRoot\\system32\\drivers\\etc\\hosts" wide //weight: 10
        $x_1_4 = "www.9505.com" ascii //weight: 1
        $x_1_5 = "4199.com" ascii //weight: 1
        $x_1_6 = "www.4199.com" ascii //weight: 1
        $x_1_7 = "www.arswp.com" ascii //weight: 1
        $x_1_8 = "piaoxue" ascii //weight: 1
        $x_1_9 = "feixue" ascii //weight: 1
        $x_1_10 = "www.feixue.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_FN_2147616883_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FN"
        threat_id = "2147616883"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {8b 45 08 8b 40 04 56 33 f6 3b c6 74 52 f6 40 06 05 74 05 8b 50 0c eb 10}  //weight: 100, accuracy: High
        $x_100_2 = {81 e9 84 c8 22 00 74 19 83 e9 04 74 10 81 e9 bc 03 00 00 0f 85 80 00 00 00 6a 33 eb 60}  //weight: 100, accuracy: High
        $x_10_3 = "\\Device\\shroud32" wide //weight: 10
        $x_10_4 = "\\DosDevices\\shroud32" wide //weight: 10
        $x_1_5 = "3shroud.exe" ascii //weight: 1
        $x_1_6 = "1shroud32.sys" ascii //weight: 1
        $x_1_7 = "5shroud32" ascii //weight: 1
        $x_1_8 = "5LEGACY_SHROUD32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_FO_2147616884_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FO"
        threat_id = "2147616884"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 c4 00 00 00 00 c7 45 c8 00 00 00 00 c7 45 fc 00 00 00 00 6a 04 6a 04 8b 4d d0 51 ff 15 8c 08 01 00 6a 04 6a 04 8b 55 dc 52 ff 15 ?? ?? ?? ?? c7 45 fc ff ff ff ff eb 22}  //weight: 10, accuracy: Low
        $x_1_2 = "AxcXBegihstnavvvsxxxxsFuckxxx" ascii //weight: 1
        $x_1_3 = "\\Device\\XueLuo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_FP_2147616885_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FP"
        threat_id = "2147616885"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {75 76 83 65 fc 00 6a 04 6a 04 53 ff 15 ?? ?? ?? ?? 6a 04 6a 04 57 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 ec 8b 00 8b 00 89 45 c0 6a 01 58 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FR_2147616887_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FR"
        threat_id = "2147616887"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 c4 00 00 00 00 c7 45 c8 00 00 00 00 c7 45 fc 00 00 00 00 6a 04 6a 04 8b 4d d0 51 ff 15 ?? ?? ?? ?? 6a 04 6a 04 8b 55 dc 52 ff 15 ?? ?? ?? ?? c7 45 fc ff ff ff ff}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 ec 8b 08 8b 11 89 55 c0 b8 01 00 00 00 c3}  //weight: 10, accuracy: High
        $x_10_3 = {8b 65 e8 8b 45 c0 89 45 d4 c7 45 fc ff ff ff ff eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FS_2147616888_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FS"
        threat_id = "2147616888"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 fc 83 7d fc 00 0f 8c ?? ?? ?? ?? 83 7d 08 05 0f 85 ?? ?? ?? ?? 8b 4d 0c 89 4d f4 c7 45 f8 00 00 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {83 7d f4 00 0f 84 ?? ?? ?? ?? 8b 55 f4 83 7a 3c 00 0f 84 ?? ?? ?? ?? b9 0c 00 00 00 bf 80 04 01 00 8b 45 f4 8b 70 3c 33 d2 89 55 ec f3 a6 74 08 1b c0 83 d8 ff 89 45 ec}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FT_2147616889_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FT"
        threat_id = "2147616889"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 0c 8b 08 8b d1 83 ea 00 74 19 4a 74 0f 51 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 59 eb 16}  //weight: 10, accuracy: Low
        $x_10_2 = {ff b0 d4 07 00 00 83 c0 04 50}  //weight: 10, accuracy: High
        $x_1_3 = "\\Device\\msiosDom32" wide //weight: 1
        $x_1_4 = "\\DosDevices\\msiosDom32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_FU_2147617022_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FU"
        threat_id = "2147617022"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {81 78 0c 00 a0 22 00 75 20 83 78 08 04 75 10 8b 46 0c 85 c0 74 09 8b 00 a3 08 09 01 00 eb 11 b8 06 02 00 c0 89 46 18 eb}  //weight: 10, accuracy: High
        $x_1_2 = "\\DosDevices\\SSDTHOOK" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FV_2147617023_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FV"
        threat_id = "2147617023"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 7d c0 00 74 ?? 8b 45 e4 8b 10 a1 ?? 05 01 00 3b 50 08 73 ?? 8b 08 fa}  //weight: 10, accuracy: Low
        $x_10_2 = {85 ff 75 08 8b 45 d4 89 46 1c eb 04}  //weight: 10, accuracy: High
        $x_1_3 = "Ce\\DarkShell" wide //weight: 1
        $x_1_4 = "\\??\\Dark2118" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_FW_2147617426_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FW"
        threat_id = "2147617426"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 35 04 09 01 00 ff 15 ?? ?? ?? ?? 68 9a 02 00 00 8a d8 ff 15 ?? ?? ?? ?? 0f b6 c3 50 68 ?? ?? ?? ?? 8d 85 00 ff ff ff 68 fd 00 00 00 50}  //weight: 10, accuracy: Low
        $x_1_2 = "ROOTKIT: OnUnload called" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FX_2147617427_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FX"
        threat_id = "2147617427"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 08 50 ff ?? ?? ?? ?? ?? 89 45 fc 83 7d fc 00 0f 8c ?? ?? ?? ?? 83 7d 08 05 0f 85 ?? ?? ?? ?? 8b 4d 0c 89 4d f4 c7 45 f8 00 00 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 f4 8b 48 28 03 0d ?? ?? ?? ?? 8b 50 2c 13 15 ?? ?? ?? ?? 8b 45 f4 89 48 28 89 50 2c 8b 4d f4 8b 51 30 03 15 ?? ?? ?? ?? 8b 41 34 13 05 ?? ?? ?? ?? 8b 4d f4 89 51 30 89 41 34}  //weight: 10, accuracy: Low
        $x_10_3 = {8b 55 f4 83 3a 00 74 0d 8b 45 f4 8b 4d 0c 03 08 89 4d 0c eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_GA_2147617538_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.GA"
        threat_id = "2147617538"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff ff 35 ?? ?? ?? ?? 68 ?? ?? 01 00 68 ?? ?? 01 00 83 3c 24 00 75 0b 8d 54 24 0c 60 0e e8 48 00 00 00 83 2c 24 05 75 01 e8 c3 78 0b c0 75 08 b8 4f 00 00 c0 c2 08 00 75 06 0e e8 f4 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 34 0b c0 75 61 8b 54 24 04 6a 64 59 33 c0 66 81 3a c6 05 75 13 66 81 7a 06 01 e8 75 0b 83 c2 08 8b 02 8d 44 10 04 eb 03 42 e2 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FY_2147617551_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FY"
        threat_id = "2147617551"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {85 f6 75 08 8b 4d d4 89 4b 1c eb}  //weight: 10, accuracy: High
        $x_10_2 = {8b 65 e8 8b 75 c0 c7 45 fc ff ff ff ff 8b 5d 0c}  //weight: 10, accuracy: High
        $x_10_3 = {8b 4d ec 8b 11 8b 02 89 45 c0 b8 01 00 00 00 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_FZ_2147617552_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!FZ"
        threat_id = "2147617552"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {eb 1e 83 3d ?? ?? ?? ?? 00 75 13 8b 4d f8 51 e8 4d 00 00 00 c7 05 ?? ?? ?? ?? 01 00 00 00 eb}  //weight: 10, accuracy: Low
        $x_1_2 = "\\Device\\wrapper64x" wide //weight: 1
        $x_1_3 = "\\DosDevices\\wrapper64x" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_GA_2147617588_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!GA"
        threat_id = "2147617588"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 33 ff 89 3d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 8b 4e 01 8b 10 8b 0c 8a 89 0d ?? ?? ?? ?? 8b 48 08 c1 e1 02}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 56 01 b9 ?? ?? ?? ?? 8d 04 90 87 08 89 0d ?? ?? ?? ?? 33 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_GB_2147617589_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.gen!GB"
        threat_id = "2147617589"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 7d 14 20 72 ?? 8b 45 10 85 c0 74 ?? 8b 08 89 0d ?? ?? ?? ?? 8b 48 04 89 0d ?? ?? ?? ?? 8b 48 08}  //weight: 10, accuracy: Low
        $x_1_2 = "\\Device\\kavsvc" wide //weight: 1
        $x_1_3 = "\\DosDevices\\kavsvc" wide //weight: 1
        $x_1_4 = "\\DosDevices\\kavlec" wide //weight: 1
        $x_1_5 = "\\Device\\kavlec" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_FE_2147618221_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.FE"
        threat_id = "2147618221"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "121"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {50 0f 20 c0 25 ff ff fe ff 0f 22 c0 58 a1 ?? ?? ?? ?? 50 68}  //weight: 100, accuracy: Low
        $x_10_2 = "\\Device\\WinHook" wide //weight: 10
        $x_10_3 = "\\WINDOWS\\system32\\fyddos.exe" wide //weight: 10
        $x_1_4 = "\\i386\\SYS.pdb" ascii //weight: 1
        $x_1_5 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_6 = "WinHook:SystemCallService: %x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_GC_2147618461_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.GC"
        threat_id = "2147618461"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 f3 ab a1 ?? ?? 01 00 83 f8 20 bf ?? ?? 01 00 76 0d 83 f8 78 77 08}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f9 67 e0 22 00 0f 85 ?? ?? ?? ?? 83 65 fc 00 6a 04 6a 04 53 ff 15 ?? ?? 01 00 83 4d fc ff 8b 1b a1 ?? ?? 01 00 39 58 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_GD_2147618526_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.GD"
        threat_id = "2147618526"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 56 00 00 68 ?? ?? ?? ?? 8d 45 ec 50 56 56 56 ff 75 fc ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 01 8b 09 [0-8] 8b 34 81 80 3e e9}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 20 c0 8b d8 81 e3 ff ff fe ff 0f 22 c3}  //weight: 1, accuracy: High
        $x_1_4 = "SystemRoot\\System32\\vs_mon.dll" wide //weight: 1
        $x_1_5 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_6 = "KeAttachProcess" ascii //weight: 1
        $x_1_7 = "ZwQueryInformationProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_GF_2147619083_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.GF"
        threat_id = "2147619083"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 08 8b 88 88 00 00 00 89 4d f8 8b 55 08 8b 82 8c 00 00 00 89 45 fc 8b 45 f8 8b 4d fc 89 48 04 8b 55 fc 8b 45 f8 89 02 b0 01}  //weight: 5, accuracy: High
        $x_1_2 = {81 7d d0 00 20 37 81 74 02}  //weight: 1, accuracy: High
        $x_1_3 = "Hello, To Process_hide" ascii //weight: 1
        $x_1_4 = "Hello, from DriverEntry" ascii //weight: 1
        $x_1_5 = "Bye, from DriverUnload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_GG_2147621114_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.GG"
        threat_id = "2147621114"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {66 8b 08 40 40 66 85 c9 75 f6 2b c2 d1 f8 33 c9 85 c0 7e 09 66 ff 0c 4e 41 3b c8 7c}  //weight: 3, accuracy: High
        $x_2_2 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 6a 20}  //weight: 2, accuracy: High
        $x_2_3 = {01 45 f8 83 c7 16 83 c6 04 4b 75 ?? fb 0f 20 c0 0d 00 00 01 00}  //weight: 2, accuracy: Low
        $x_3_4 = {01 00 68 c6 81 ?? ?? 01 00 c3 83 c1 16 81 f9 0d 00 ab ab 83}  //weight: 3, accuracy: Low
        $x_1_5 = {44 00 77 00 53 00 68 00 69 00 65 00 6c 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 00 41 00 56 00 44 00 52 00 56 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_KG_2147621333_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KG"
        threat_id = "2147621333"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Device\\RESSDT" wide //weight: 1
        $x_1_2 = {81 fa c0 20 22 00 0f 84 ?? 00 00 00 81 fa 4b e1 22 00 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 07 89 04 b1 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KH_2147621334_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KH"
        threat_id = "2147621334"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 6d f4 04 00 61 25 74 ?? 83 6d f4 04 74}  //weight: 1, accuracy: Low
        $x_1_2 = {50 33 c0 33 c0 33 c0 33 c0 33 c0 33 c0 58}  //weight: 1, accuracy: Low
        $x_1_3 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 a1 ?? ?? ?? ?? 8b 40 01 8b 0d ?? ?? ?? ?? 8b 09 c7 04 81 ?? ?? ?? ?? 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KI_2147621335_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KI"
        threat_id = "2147621335"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ObReferenceObjectByName" ascii //weight: 1
        $x_1_2 = "\\Driver\\ProtectedC" wide //weight: 1
        $x_1_3 = {81 38 59 68 e8 03}  //weight: 1, accuracy: High
        $x_1_4 = {81 78 04 00 00 e8 0e}  //weight: 1, accuracy: High
        $x_1_5 = {8b 0c b3 0b c9 74 ?? 8b 79 04 66 8b 07 66 83 f8 03 75 ?? 8b 47 10 0b c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KJ_2147621336_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KJ"
        threat_id = "2147621336"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d fc 2b c1 8b 0a 03 c7 3b 04 99 8d 0c 99 74 02 89 01}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fc 8b 4d fc c1 e0 09 c1 e1 02 8d 80 ?? ?? ?? ?? 89 84 0d ?? ?? ff ff 05 ?? ?? ?? ?? 89 84 0d ?? ?? ff ff 05 ?? ?? ?? ?? ff 45 fc}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 7d 08 05 ?? ?? ?? ?? 89 45 ?? 83 65 ?? 00 8b 47 3c 8b 74 38 78 8b 44 3e 20 03 f7 03 c7 8b 5e 1c 8b 4e 24 03 df 03 cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KL_2147621343_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KL"
        threat_id = "2147621343"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 66 81 38 4d 5a 0f 85 ?? 00 00 00 8b 50 3c 03 55 08 81 3a 50 45 00 00 0f 85 9c 00 00 00 8b 42 34 89 45 ?? 8b 82 a0 00 00 00 8b 92 a4 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {fa 50 0f 20 c0 89 45 ?? 25 ff ff fe ff 0f 22 c0 58 52 8b c6 c1 e0 02 03 45 ?? 50 e8 ?? 00 00 00 50 8b 45 ?? 0f 22 c0 58 fb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 3c 03 c3 89 45 ?? 8b 45 ?? 81 38 50 45 00 00 74 ?? 53 e8 ?? ?? 00 00 e9 ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KM_2147621400_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KM"
        threat_id = "2147621400"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_2 = "\\Device\\WinHook" wide //weight: 1
        $x_1_3 = "*WinHook:Hook System Call Service*" ascii //weight: 1
        $x_1_4 = {50 0f 20 c0 25 ff ff fe ff 0f 22 c0 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KN_2147621507_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KN"
        threat_id = "2147621507"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 8b 0d ?? ?? ?? ?? 8b 09 8b 14 9d ?? ?? ?? ?? 39 14 99 74 06 8d 0c 99 f0 87 11 43 3b 1d ?? ?? ?? ?? 7c dd a1 ?? ?? ?? ?? 0b c0 74 0f 80 38 e9 75 0a c6 00 2b c7 40 01 e1 c1 e9 02 0f 20 c0 0d 00 00 01 00 0f 22 c0 61 b8 82 01 00 c0 c9 c2 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KO_2147621508_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KO"
        threat_id = "2147621508"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ObReferenceObjectByName" ascii //weight: 1
        $x_1_2 = "NdisRegisterProtocol" ascii //weight: 1
        $x_1_3 = "\\Driver\\Tcpip" wide //weight: 1
        $x_1_4 = "\\Device\\Ipfilterdriver" wide //weight: 1
        $x_1_5 = {80 39 e8 75 ?? 8b 51 01 8d 54 0a 05 81 3a 58 83 c0 03 75 ?? 8b 51 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KP_2147621509_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KP"
        threat_id = "2147621509"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Device\\agony" wide //weight: 1
        $x_1_2 = "\\DosDevices\\agony" wide //weight: 1
        $x_1_3 = {8b 48 01 8b 12 8b 0c 8a 89 0d ?? ?? ?? ?? fa 8b 40 01 8b 15 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8d 04 82 87 08 89 0d ?? ?? ?? ?? fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KQ_2147621510_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KQ"
        threat_id = "2147621510"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Device\\Harddisk0\\DR0" wide //weight: 1
        $x_1_2 = "\\Driver\\atapi" wide //weight: 1
        $x_1_3 = "\\Driver\\nvata" wide //weight: 1
        $x_1_4 = "\\FileSystem\\Ntfs" wide //weight: 1
        $x_1_5 = "ObReferenceObjectByName" ascii //weight: 1
        $x_1_6 = {8b 41 60 fe 49 23 83 e8 24 56 89 41 60 89 50 14 0f b6 00 8b 72 08 51 52 ff 54 86 38 5e 5d c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KR_2147621603_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KR"
        threat_id = "2147621603"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 0c 3d 24 0c 0b 83 74 ?? 3d 28 0c 0b 83 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 04 3b 05 ?? ?? ?? ?? 7c 07 b8 20 16 01 00 eb 08 6b c0 64 05 ?? ?? ?? ?? c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_GI_2147621632_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.GI"
        threat_id = "2147621632"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 10 24 08 00 0f ?? ?? 00 00 00 81 f9 08 20 22 00 0f ?? ?? 00 00 00 81 f9 17 e4 22 00 0f ?? ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {03 00 12 00 89 45 ?? 0f 85 ?? ?? 00 00 85 c0 0f 8c ?? ?? 00 00 57 6a 05 59 8d 7d ?? f3 a5 81 7d ?? 00 04 00 00 0f 85 28 01 00 00 83 7d ?? 00 0f 85 ?? ?? 00 00 81 7d ?? 00 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KT_2147621635_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KT"
        threat_id = "2147621635"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Device\\Tcp" wide //weight: 1
        $x_1_2 = {0f b7 4c 0a 14 81 e1 00 ff 00 00 c1 f9 08 03 c1 [0-5] 75 ?? 8b 55 ?? 69 d2}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d 10 81 79 04 02 01 00 00 75 ?? 8b 55 0c 8b 42 1c 33 d2 b9 18 00 00 00 f7 f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KU_2147621701_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KU"
        threat_id = "2147621701"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 1b c0 20 04 [0-8] 74 ?? 83 e8 04 74}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 06 55 8b ec 51 c6 46 04 8b}  //weight: 1, accuracy: High
        $x_1_3 = {81 39 8b ff 55 8b 75 ?? 81 79 04 ec 56 64 a1 75 ?? 81 79 08 24 01 00 00 75 ?? 81 79 0c 8b 75 08 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KV_2147621702_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KV"
        threat_id = "2147621702"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 06 8d 04 3e 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 c4 0c 85 c0 75 ?? 89 35 ?? ?? ?? ?? 46 81 fe 00 30 00 00 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 00 25 ff ff 00 00 2d 21 04 00 00 74 c7 05 ?? ?? ?? ?? 1e 00 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KW_2147621703_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KW"
        threat_id = "2147621703"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3e 0e 0f 85 ?? ?? ?? ?? 81 7e 0c 04 20 22 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {3b 5d 1c 75 09 c7 45 2c 06 00 00 80 eb 06 8b 45 30 83 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KX_2147621798_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KX"
        threat_id = "2147621798"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 24 01 74 ?? 83 7d 24 02 74 ?? 83 7d 24 26 74 ?? 83 7d 24 03 74 ?? 83 7d 24 25 74 ?? 83 7d 24 0c 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {83 39 00 74 ?? 8b 55 ?? 8b 45 0c 03 02 89 45 0c eb 07 c7 45 0c 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KY_2147621799_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KY"
        threat_id = "2147621799"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 ff 00 8b 45 24 83 20 00 8b 45 24 83 60 04 00 8b 45 20 89 45 ?? 8b 45 ?? 89 45 ?? 81 6d ?? 04 00 61 25}  //weight: 1, accuracy: Low
        $x_1_2 = {3b 45 1c 75 09 c7 45 ?? 06 00 00 80 eb 06 8b 45 ?? 83 20 00 8d 45 ?? 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_KZ_2147622077_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.KZ"
        threat_id = "2147622077"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 4b 04 8b 3b 03 7d ?? 8b c1 8d 73 08 c1 e9 02 f3 a5}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 45 08 83 c3 18 8b 45 08 3b 47 7c 7c}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 68 00 00 10 00 6a 01 8d 45 ?? 50 56 68 e8 03 00 00 56 8d 45 ?? 50 6a ff ff 75 ?? ff 15 ?? ?? ?? ?? 3d 03 00 00 40 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LA_2147622078_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LA"
        threat_id = "2147622078"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 87 ?? ?? ?? ?? 33 c9 8a 0d ?? ?? ?? ?? 33 c1 8b 4d ?? 88 04 0f 47 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {53 8a 1c 11 32 1d ?? ?? ?? ?? 88 1a 42 48 75 f1 5b}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 08 8d 45 ?? 50 6a 09 6a ff ff 15 ?? ?? ?? ?? f6 45 08 02 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LB_2147622079_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LB"
        threat_id = "2147622079"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c2 08 00 8b 45 0c 0f b7 04 43 8b 04 87 eb ed}  //weight: 1, accuracy: High
        $x_1_2 = {8b 7e 1c 8b 46 20 8b 5e 24 83 65 0c 00 03 f9 03 c1 03 d9 83 7e 18 00 76}  //weight: 1, accuracy: High
        $x_1_3 = {8b ca 83 e1 03 f3 a4 81 78 20 32 54 76 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LC_2147622080_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LC"
        threat_id = "2147622080"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 89 45 18 76 ?? 89 75 20 eb 03 8b ?? 1c 8b ?? be 6a 00 ?? ff 15 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 85 c0 74 0c 8b 45 1c 83 ?? b8 00 ff 4d 18}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 10 c1 e1 02 85 f6 8b 14 01 75 03 33 c0 c3 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 a1 ?? ?? ?? ?? 8b 40 10 89 34 01 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LD_2147622279_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LD"
        threat_id = "2147622279"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 4e 41 4d 45 5f 54 4f 5d 00 5b 4d 41 49 4c 5f 54 4f 5d 00 5b 54 48 45 42 41 54 5f 4d 45 53 53 49 44 5d 00 5b 4f 55 54 4c 4f 4f 4b 5f 4d 45 53 53 49 44 5d}  //weight: 1, accuracy: High
        $x_1_2 = {c6 00 e9 8b ?? 2b ?? 89 ?? 01 8b 45 0c 2b [0-4] 83 e8 05 89 ?? 01 c6 ?? e9}  //weight: 1, accuracy: Low
        $x_1_3 = {80 f9 40 75 06 81 cb 00 01 00 00 80 f9 80 75 ?? 0b df eb ?? 80 f9 40 75 06 81 cb 00 01 00 00 80 f9 80 75 06 81 cb 00 04 00 00 3c 04 75 ?? 8a 06 24 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LE_2147622468_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LE"
        threat_id = "2147622468"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\DosDevices\\C:\\windows\\system32\\%ws" wide //weight: 1
        $x_1_2 = {85 c0 74 32 8b 75 2c 8b 7d 24 83 6d 24 14 83 6d 2c 14 8b c3 2b 45 1c 48 8d 0c 80 c1 e1 02 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 ff 4d 1c f3 a4 8b 75 18 8b 7d 20 4b}  //weight: 1, accuracy: High
        $x_1_3 = {8d 34 10 f3 a5 8b 4b 3c 8b c3 2b 44 19 34 33 ff 33 d2 39 3d ?? ?? ?? ?? 7e 14 8b 0d ?? ?? ?? ?? 8d 0c 91 01 01 42 3b 15 ?? ?? ?? ?? 7c ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LF_2147622469_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LF"
        threat_id = "2147622469"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Device\\WINDOWSEXX" wide //weight: 1
        $x_1_2 = {8b 7d 0c 8b 47 60 8b 48 0c 8b 58 10 8b 77 3c 8b 40 04 89 45 ?? 81 f9 d7 e0 22 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 7d 0c 8b 45 ?? 85 c0 75 08 8b 4d ?? 89 4f 1c eb 04 83 67 1c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LG_2147622470_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LG"
        threat_id = "2147622470"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services" wide //weight: 1
        $x_1_2 = {53 53 53 53 50 68 00 00 00 40 ff b5 ?? ?? ff ff ff 15 ?? ?? ?? ?? eb 12 50 68 00 00 00 82 ff b5 ?? ?? ff ff ff 15 ?? ?? ?? ?? 5e 5b}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 75 1c 8d 45 ?? ff 75 18 ff 75 14 6a 00 50 ff 75 0c ff 15 ?? ?? ?? ?? ff 75 0c 8b f0 ff 15 ?? ?? ?? ?? 8b c6 5e c9 c2 18 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LH_2147622471_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LH"
        threat_id = "2147622471"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "KdDisableDebugger" ascii //weight: 1
        $x_1_2 = "\\Device\\HardDiskVolume%d" wide //weight: 1
        $x_1_3 = {83 e8 24 c6 00 0d 8b 8d ?? ?? ff ff 8b 49 08 8b 49 08 89 48 14 8b 8d ?? ?? ff ff 89 48 18 8d 8d ?? ?? ff ff c7 40 0c 73 00 09 00 c7 40 08 08 00 00 00 89 48 10 c7 40 04 10 01 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LI_2147622689_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LI"
        threat_id = "2147622689"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\registry\\machine\\system\\CurrentControlSet\\Enum\\Root\\LEGACY_%ws" wide //weight: 1
        $x_1_2 = {0f b7 00 3d 93 08 00 00 74 ?? 3d 28 0a 00 00 74 ?? 3d ce 0e 00 00 75 ?? c7 05 ?? ?? ?? ?? 05 12 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 75 08 a1 ?? ?? ?? ?? 81 e6 ff 0f 00 00 85 c0 74 ?? 3b 70 18 73 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 50 10 8b ce 8b 75 10 c1 e1 02 8b 14 11 89 16 8b 40 10 8b 55 0c 89 14 01 ff 75 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LJ_2147622690_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LJ"
        threat_id = "2147622690"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0a ff 71 0c ff 71 08 ff 71 04 52 50 e8 ?? ?? ?? ?? 8b f8 33 c0 85 f6 74 0a 0f b6 06 3d b8 00 00 00 74 ?? 83 7d 14 00 75 ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d7 84 c0 74 ?? 8b 46 08 0f b7 08 51 8d 8d ?? ?? ?? ?? 51 ff 70 04 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 85 c0 59 59 75 b8 22 00 00 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LK_2147622691_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LK"
        threat_id = "2147622691"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\KnownDlls\\KnownDllPath" wide //weight: 1
        $x_1_2 = {8b 4d f4 8b 41 08 8b 78 08 8b 40 0c 89 7d ?? 89 45 ?? ff 15 ?? ?? ?? ?? 8d 45 ?? 50 53 53 6a 70 53 53 8d 45 ?? 50}  //weight: 1, accuracy: Low
        $x_1_3 = {89 46 50 8b 46 60 89 5e 64 83 e8 24 c6 00 03 c6 40 01 00 8b 4b 08 8b 49 08 89 48 14 8b 4d 14 89 48 04 8b 4d 18 89 58 18 8b 11 89 50 0c 8b 49 04 89 48 10 8b 46 60 83 e8 24 c7 40 1c ?? ?? ?? ?? 89 78 20 c6 40 03 e0 8b 43 08 8b 48 08 8b d6 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LL_2147622732_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LL"
        threat_id = "2147622732"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Device\\Tcp" wide //weight: 1
        $x_1_2 = "\\FileSystem\\ntfs" wide //weight: 1
        $x_1_3 = {8b 5f 60 85 db 74 ?? 80 3b 0c 75 ?? 80 7b 01 01 75 ?? 83 7f 18 00 7c ?? 83 7f 1c 00 74 ?? 57 e8 ?? ?? ?? ?? 8b f0 85 f6 74 ?? f6 43 02 02 74}  //weight: 1, accuracy: Low
        $x_1_4 = {85 c0 7c 18 8b 45 ?? 8b 48 0c 89 0d ?? ?? ?? ?? 8b 48 10 03 48 0c 89 0d ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LM_2147622733_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LM"
        threat_id = "2147622733"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Device\\msdirectx" wide //weight: 1
        $x_1_2 = "\\ObjectTypes\\Process" ascii //weight: 1
        $x_1_3 = {81 7d fc f4 01 00 00 0f 8f ?? ?? 00 00 6a 00 8b 95 ?? ?? ff ff 03 55 ?? 52 8d 85 ?? ?? ff ff 50 e8 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 83 bd ?? ?? ff ff 29 75 ?? 6a 00 8b 8d ?? ?? ff ff 03 4d ?? 51 8d 95 ?? ?? ff ff 52 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LN_2147622734_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LN"
        threat_id = "2147622734"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" wide //weight: 1
        $x_1_2 = {33 ff 89 7d ?? 89 7d ?? c7 45 ?? 47 90 a4 db 66 c7 45 ?? 40 1d 66 c7 45 ?? bd 4c c6 45 ?? 9e c6 45 ?? e4 c6 45 ?? f4 c6 45 ?? 8c c6 45 ?? e4 c6 45 ?? 91 c6 45 ?? 95 c6 45 ?? 28 8b 75 08 8d 46 08 80 38 00 74}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4c 24 0c 8b 01 3d 13 01 00 00 75 14 8d 81 88 00 00 00 ff b0 d0 07 00 00 50 e8 ?? ?? ff ff eb 2a 3d 11 01 00 00 75 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LP_2147622760_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LP"
        threat_id = "2147622760"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\SystemRoot\\SYSTEM32\\ntoskrnl.exe" wide //weight: 1
        $x_1_2 = {8b 0a ff 71 0c ff 71 08 ff 71 04 52 50 e8 ?? ?? ff ff 8b f8 33 c0 85 db 74 0a 0f b6 03 3d b8 00 00 00 74 ?? 85 f6 75}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 f3 a6 74 05 1b c0 83 d8 ff 85 c0 75 0a c7 85 ?? ?? ff ff 01 00 00 00 83 bd ?? ?? ff ff 00 74 10 83 bd ?? ?? ff ff 01 74 07 b8 22 00 00 c0 eb ?? ff 75 1c ff 75 18 ff b5 ?? ?? ff ff ?? ff 75 0c ff b5 ?? ?? ff ff ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LQ_2147622824_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LQ"
        threat_id = "2147622824"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 6d f4 04 00 61 25 0f 84 ?? ?? ?? ?? 83 6d f4 04 74 ?? 83 6d f4 04 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 18 8b 40 04 33 d2 6a 14 59 f7 f1 89 45 ?? 8b 45 28 89 45 ?? 83 65 ?? 00 eb 07 8b 45 ?? 40 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 83 ?? ?? 00 00 83 3d ?? ?? ?? ?? 00 74 ?? 8b 45 ?? 6b c0 14 8b 4d ?? 8b 44 01 0c 3b 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LR_2147622918_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LR"
        threat_id = "2147622918"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\DosDevices\\ProReg" wide //weight: 1
        $x_1_2 = "???;System;SMSS.EXE;CSRSS.EXE;LSASS.EXE;WINLOGON.EXE;SERVICES.EXE;svchost.exe;" ascii //weight: 1
        $x_1_3 = {8a 08 40 84 c9 75 f9 2b c2 b9 ff 03 00 00 2b c8 51 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LS_2147622919_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LS"
        threat_id = "2147622919"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_2 = {ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 ?? ?? 01 00 89 45 ?? 85 c0 0f 8c ?? ?? 00 00 83 7d 24 03 0f 85 ?? ?? 00 00 c7 45 ?? ?? ?? 01 00 89 5d ?? 83 65 ?? 00 33 c0 39 03 0f 94 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 03 59 8b bd ?? ?? ff ff 8b 95 ?? ?? ff ff 8b f2 33 c0 f3 a6 0f 84 ?? ?? 00 00 8a 02 3c e9 74 08 3c cc 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_GP_2147623067_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.GP"
        threat_id = "2147623067"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 65 fc 00 6a 04 6a 04 53 ff 15 ?? ?? ?? ?? 6a 04 6a 04 57 ff 15 ?? ?? ?? ?? 83 4d fc ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 08 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 07 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 83 65 e4 00 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LU_2147623125_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LU"
        threat_id = "2147623125"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\shellserviceobjectdelayload\\network" wide //weight: 1
        $x_1_2 = "{fc055e7d-8144-4706-8586-2f1c49fcdd2a}" wide //weight: 1
        $x_1_3 = {80 7d ff 00 5f 5e 74 10 80 3d ?? ?? 01 00 00 74 07 b8 22 00 00 c0 eb 0c ff 75 0c ff 75 08 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LV_2147623126_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LV"
        threat_id = "2147623126"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DP_PROTECTION" ascii //weight: 1
        $x_1_2 = {ff 75 08 e8 ?? ?? ff ff 84 c0 74 0b b8 0f 00 00 c0 83 4d fc ff eb}  //weight: 1, accuracy: Low
        $x_1_3 = {83 7d e4 00 0f 85 ?? ?? 00 00 83 7d 24 03 0f 85 ?? ?? 00 00 8b fb 89 7d dc 83 65 e0 00 85 ff 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LW_2147623127_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LW"
        threat_id = "2147623127"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\SystemRoot\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_2 = "\\Device\\RegGuard" wide //weight: 1
        $x_1_3 = {83 7d 14 01 75 13 ff 75 1c ff 75 18 e8 ?? ?? ?? ?? 84 c0 74 04 33 c0 eb 18 ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 ?? ?? 01 00 c9 c2 18 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_NU_2147623165_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.NU"
        threat_id = "2147623165"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 79 73 74 65 6d 72 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 25 73 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 ?? ?? ?? ?? 49 45 58 50 4c 4f 52 45 2e 45 58 45 ?? ?? ?? ?? 49 4e 45 54 43 50 4c 2e 43 50 4c 00 53 79 73 74 65 6d ?? ?? 75 73 65 72 69 6e 69 74 2e 65 78 65 ?? ?? ?? ?? 65 78 70 6c 6f 72 65 72 2e 65 78 65 ?? ?? ?? ?? 31 32 37 2e 30 2e 30 2e 32 ?? ?? ?? 77 77 77 2e 35 35 36 36 64 68 2e 63 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "\\DosDevices\\KappaAvb" wide //weight: 1
        $x_1_3 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 72 00 75 00 6e 00 6f 00 6e 00 63 00 65 00 ?? ?? 7a 00 68 00 61 00 6f 00 64 00 61 00 6f 00 31 00 32 00 33 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_4 = "twww.5566dh.cn?tg=%d" wide //weight: 1
        $x_1_5 = "\\Software\\Microsoft\\Internet Explorer\\Main" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_GQ_2147623601_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.GQ"
        threat_id = "2147623601"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 20 00 80 be 0d 00 00 c0 74 ?? 3d 04 20 00 80 75}  //weight: 1, accuracy: Low
        $x_1_2 = "CmUnRegisterCallback" ascii //weight: 1
        $x_1_3 = "IofCompleteRequest" ascii //weight: 1
        $x_1_4 = "SERVICES\\MNMSRVC" wide //weight: 1
        $x_1_5 = "SERVICES\\IMAPISERVICE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_GR_2147623669_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.GR"
        threat_id = "2147623669"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 00 b8 01 00 00 83 c0 04 8b 08 89 0d ?? ?? ?? 00 c7 00 00 c2 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = "MmGetSystemRoutineAddress" ascii //weight: 1
        $x_1_3 = "MmFlushImageSection" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_NV_2147624045_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.NV"
        threat_id = "2147624045"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {cc 6c 73 30 73 73 2e 65 78 65 1d 00 81 ?? ?? 90 90 90 90 74 ?? ?? 3d 78 09 00 00 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {68 72 79 41 00 68 65 63 74 6f 68 6d 44 69 72 68 79 73 74 65 68 47 65 74 53 e8}  //weight: 1, accuracy: High
        $x_1_3 = {4b 65 53 65 72 76 69 63 65 44 00 00 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_LX_2147624095_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.LX"
        threat_id = "2147624095"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 56 8b 78 18 8b 70 48 39 7e 18 74 04 8b 36 eb f7 68 ?? ?? 01 00 ba ?? ?? 01 00 39 3a 0f 85 ?? ?? ?? ?? 74 05 60 8b 74 24 24 8b 7c 24 28 fc b2 80 33 db a4 b3 02}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 64 59 33 c0 66 81 3a c6 05 75 13 66 81 7a 06 01 e8 75 0b 83 c2 08 8b 02 8d 44 10 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_NW_2147624679_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.NW"
        threat_id = "2147624679"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 75 d8 66 c7 45 ?? 5a 00 66 c7 45 ?? 77 00 66 c7 45 ?? 51 00 66 c7 45 ?? 75 00 66 c7 45 ?? 65 00 66 c7 45 ?? 72 00 66 c7 45 ?? 79 00 66 c7 45 ?? 53 00 66 c7 45 ?? 79 00 66 c7 45 ?? 73 00 66 c7 45 ?? 74 00 66 c7 45 ?? 65 00 66 c7 45 ?? 6d 00 66 c7 45 ?? 49 00 66 c7 45 ?? 6e 00 66 c7 45 ?? 66 00 66 c7 45 ?? 6f 00 66 c7 45 ?? 72 00 66 c7 45 ?? 6d 00 66 c7 45 ?? 61 00 66 c7 45 ?? 74 00 66 c7 45 ?? 69 00 66 c7 45 ?? 6f 00 66 c7 45 ?? 6e 00 66 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_NX_2147624680_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.NX"
        threat_id = "2147624680"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 75 f8 66 c7 45 ?? 5a 00 66 c7 45 ?? 77 00 66 c7 45 ?? 51 00 66 c7 45 ?? 75 00 66 c7 45 ?? 65 00 66 c7 45 ?? 72 00 66 c7 45 ?? 79 00 66 c7 45 ?? 53 00 66 c7 45 ?? 79 00 66 c7 45 ?? 73 00 66 c7 45 ?? 74 00 66 c7 45 ?? 65 00 66 c7 45 ?? 6d 00 66 c7 45 ?? 49 00 66 c7 45 ?? 6e 00 66 c7 45 ?? 66 00 66 c7 45 ?? 6f 00 66 c7 45 ?? 72 00 66 c7 45 ?? 6d 00 66 c7 45 ?? 61 00 66 c7 45 ?? 74 00 66 c7 45 ?? 69 00 66 c7 45 ?? 6f 00 66 c7 45 ?? 6e 00 66 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_NY_2147624681_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.NY"
        threat_id = "2147624681"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 d4 01 00 00 c0 66 c7 45 ?? 5a 00 66 c7 45 ?? 77 00 66 c7 45 ?? 51 00 66 c7 45 ?? 75 00 66 c7 45 ?? 65 00 66 c7 45 ?? 72 00 66 c7 45 ?? 79 00 66 c7 45 ?? 53 00 66 c7 45 ?? 79 00 66 c7 45 ?? 73 00 66 c7 45 ?? 74 00 66 c7 45 ?? 65 00 66 c7 45 ?? 6d 00 66 c7 45 ?? 49 00 66 c7 45 ?? 6e 00 66 c7 45 ?? 66 00 66 c7 45 ?? 6f 00 66 c7 45 ?? 72 00 66 c7 45 ?? 6d 00 66 c7 45 ?? 61 00 66 c7 45 ?? 74 00 66 c7 45 ?? 69 00 66 c7 45 ?? 6f 00 66 c7 45 ?? 6e 00 66 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_GS_2147624845_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.GS"
        threat_id = "2147624845"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0c 8b 45 08 ff 70 04 ff 15 ?? ?? ?? ?? eb 04}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 53 ff 15 ?? ?? ?? ?? 6a 04 6a 04 56 ff 15 ?? ?? ?? ?? 83 4d fc ff 8b 1b}  //weight: 1, accuracy: Low
        $x_5_3 = {53 00 70 00 79 00 77 00 61 00 72 00 65 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 20 00 [0-8] 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_AQ_2147627223_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.AQ"
        threat_id = "2147627223"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 0d ?? ?? ?? 00 8b 40 01 8b 09 83 ec 14 56 8b 34 81 80 3e e9 75 11 8b 45 ?? 2b c6 83 e8 05 39 46 01 75 04 33 c0 eb 77}  //weight: 1, accuracy: Low
        $x_1_2 = "ZwQueryValueKey" ascii //weight: 1
        $x_1_3 = "ZwEnumerateKey" ascii //weight: 1
        $x_1_4 = "ZwCreateFile" ascii //weight: 1
        $x_1_5 = "ZwCreateSection" ascii //weight: 1
        $x_1_6 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_7 = "\\SystemRoot\\System32\\vs_mon.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_HI_2147627821_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.HI"
        threat_id = "2147627821"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Device\\Driver304315" wide //weight: 1
        $x_1_2 = "AppInit_DLLs" wide //weight: 1
        $x_1_3 = "Device\\Tcp" wide //weight: 1
        $x_3_4 = {68 3f 00 0f 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f8 85 ff 0f 8c ?? 00 00 00 56 bf 00 04 00 00 68 4e 4d 64 61 57 6a 00}  //weight: 3, accuracy: Low
        $x_3_5 = {8b 48 14 85 c9 74 0f 39 71 04 75 05 8b 16 89 51 04 8b 49 18 eb ed 8b 40 10 eb d9}  //weight: 3, accuracy: High
        $x_3_6 = {55 68 10 27 00 00 8b 54 ?? ?? 8b 44 ?? ?? 52 50 e8 ?? ?? 00 00 8b da 55 8b f8 6a 19 53 57 e8 ?? ?? 00 00 55 68 e8 03 00 00 83 c0 61}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_GX_2147628020_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.GX"
        threat_id = "2147628020"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 0f 20 c0 25 ff ff fe ff 0f 22 c0 58 80 7d 08 00}  //weight: 2, accuracy: High
        $x_2_2 = {8b 49 01 8b 12 b8 ?? ?? 01 00 8d 0c 8a 87 01 a3 ?? ?? 01 00}  //weight: 2, accuracy: Low
        $x_2_3 = "KeServiceDescriptorTable" ascii //weight: 2
        $x_1_4 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_5 = "ZwQueryDirectoryFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_GY_2147628022_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.GY"
        threat_id = "2147628022"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 58}  //weight: 2, accuracy: High
        $x_2_2 = {8b 50 01 8b 31 8b 14 96 89 15 ?? ?? 01 00 8b 40 01 8b 09 c7 04 81 ?? ?? 01 00 50 8b 44 24 08 0f 22 c0}  //weight: 2, accuracy: Low
        $x_1_3 = "ZwQueryDirectoryFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_GZ_2147628490_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.GZ"
        threat_id = "2147628490"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 64 00 61 00 71 00 64 00 72 00 76 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 45 e4 8b 00 89 04 9f 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 33 ff eb 1b 8b 45 ec 8b 00 8b 00 89 45 dc 33 c0 40 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_HG_2147631250_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.HG"
        threat_id = "2147631250"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "??\\C:\\WINDOWS\\system32\\" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {89 48 40 c7 40 34 ?? ?? ?? ?? 33 c9 33 c0 f6 90 ?? ?? ?? ?? 40 3d 00 01 00 00 7c f2}  //weight: 1, accuracy: Low
        $x_1_4 = {7e 40 c7 45 fc ?? ?? ?? ?? 8d 34 bd ?? ?? ?? ?? 83 3e 00 75 21 ff 75 fc e8 ?? ?? ?? ?? 85 c0 75 06 c7 06 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_HQ_2147638434_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.HQ"
        threat_id = "2147638434"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\??\\TXQQ" wide //weight: 1
        $x_1_2 = "Image File Execution Options" wide //weight: 1
        $x_1_3 = {8b 48 60 83 e9 24 89 4d ?? 8b 55 ?? c7 42 1c ?? ?? ?? ?? 8b 45}  //weight: 1, accuracy: Low
        $x_1_4 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 45 ?? 8b 4d ?? 8b 55 ?? 8b 12 89 14 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_HR_2147639083_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.HR"
        threat_id = "2147639083"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 40 04 89 78 10 8b 40 0c 3b ?? 75 f6}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 40 01 8b 15 ?? ?? ?? ?? 8d 04 82 87 08 89 0d}  //weight: 1, accuracy: Low
        $x_1_3 = "Help\\svchost.exe" ascii //weight: 1
        $x_1_4 = "\\Device\\svchost" wide //weight: 1
        $x_2_5 = "\\i386\\ROOT_DRIVER.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_HU_2147640985_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.HU"
        threat_id = "2147640985"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 01 4d f8 0f b7 4d fa 0f b7 55 fc c1 e2 10 0b ca}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 88 88 01 00 00 8b 55 ?? 0f b7 82 8e 01 00 00 c1 e0 10 0b c8}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 9d 00 00 00 74 ?? 0f b6 4d ?? 81 f9 b8 00 00 00 74 ?? 0f b6 55 ?? 83 fa 5b}  //weight: 1, accuracy: Low
        $x_1_4 = ":\\ROOTKITS\\wsh\\HIDEKEY\\" ascii //weight: 1
        $x_1_5 = "got scancode %02X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_IF_2147651956_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.IF"
        threat_id = "2147651956"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 44 00 72 00 69 00 76 00 65 00 72 00 5c 00 54 00 63 00 70 00 69 00 70 00 00 00 74 63 70 69 70 2e 73 79 73 00 00 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 74 00 63 00 70 00 69 00 70 00 2e 00 73 00 79 00 73}  //weight: 1, accuracy: High
        $x_1_2 = {3d 23 20 11 88}  //weight: 1, accuracy: High
        $x_1_3 = {3d a3 20 11 88}  //weight: 1, accuracy: High
        $x_1_4 = {3d e3 20 11 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_OG_2147708900_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.OG!bit"
        threat_id = "2147708900"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\Re1986SDTDOS" ascii //weight: 1
        $x_1_2 = "\\NetBot\\i386\\ReSSDT.pdb" ascii //weight: 1
        $x_1_3 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 8b 4d c8 89 04 99 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_OI_2147716748_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.OI!bit"
        threat_id = "2147716748"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 70 68 70 3f 70 3d 00 78 6a 77 6d 61 78 2e 7a 6f 6c 73 65 61 72 63 68 2e 63 6f 6d}  //weight: 1, accuracy: High
        $x_1_2 = {33 00 36 00 30 00 41 00 6e 00 74 00 69 00 48 00 61 00 63 00 6b 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 00 00 61 00 62 00 6f 00 75 00 74 00 3a 00 62 00 6c 00 61 00 6e 00 6b 00 00 00 68 00 61 00 6f 00 2e 00 33 00 36 00 30 00 2e 00 63 00 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_OK_2147732960_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.OK!bit"
        threat_id = "2147732960"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "http://www.woniulock.com/tuguan.php?name=" wide //weight: 5
        $x_1_2 = "[InjectByHook32]" ascii //weight: 1
        $x_1_3 = "\\??\\C:\\Program Files\\Common Files\\System\\safemon.dat" wide //weight: 1
        $x_1_4 = "iexplore.exe*chrome.exe*2345explorer.exe*theworld.exe*" ascii //weight: 1
        $x_1_5 = {73 00 75 00 6e 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 [0-16] 67 00 6f 00 6d 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 63 00 6e 00 [0-16] 6a 00 64 00 2e 00 63 00 6f 00 6d 00 [0-16] 74 00 6d 00 61 00 6c 00 6c 00 [0-16] 64 00 65 00 74 00 61 00 69 00 6c 00 [0-16] 74 00 61 00 6f 00 62 00 61 00 6f 00}  //weight: 1, accuracy: Low
        $x_2_6 = {8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 15 ?? ?? ?? 00 73 1c 8b 85 ?? ?? ?? ff 03 45 f8 0f be 08 83 f1 ?? 8b 95 ?? ?? ?? ff 03 55 f8 88 0a eb d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Rootkitdrv_OL_2147734115_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.OL!bit"
        threat_id = "2147734115"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "blog.163.com/molly_yadagroup/profile" ascii //weight: 1
        $x_1_2 = "t.qq.com/chuanqifuzhu2018" ascii //weight: 1
        $x_1_3 = "h3dDSEU6c3991A==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Rootkitdrv_OM_2147734509_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Rootkitdrv.OM!bit"
        threat_id = "2147734509"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Rootkitdrv"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f8 48 75 7a 48 8b 44 24 28 0f b6 40 01 3d 8d 00 00 00 75 6a 48 8b 44 24 28 0f b6 40 02 83 f8 0d 75 5c 48 8b 44 24 28 0f b6 40 07 83 f8 48 75 4e 48 8b 44 24 28 0f b6 40 08 3d 8b 00 00 00 75 3e 48 8b 44 24 28 0f b6 40 09 3d d7 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "msvcdlx32.dat" ascii //weight: 1
        $x_1_3 = "bctlist.dat" ascii //weight: 1
        $x_1_4 = "fk_drv.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

