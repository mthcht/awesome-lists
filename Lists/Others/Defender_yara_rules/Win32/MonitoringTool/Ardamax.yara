rule MonitoringTool_Win32_Ardamax_14849_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ardamax Keylogger" wide //weight: 1
        $x_1_2 = {41 00 4b 00 4c 00 4d 00 57 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 00 73 00 6e 00 6d 00 73 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 22 20 61 6c 74 3d 22 22 2f 3e 3c 2f 70 3e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\AKV.000" wide //weight: 1
        $x_1_2 = "Ardamax Keylogger" wide //weight: 1
        $x_1_3 = "%b_%d_%Y__%H_%M_%S.jpg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "MSG-968C3043-1128-43dc-83A9-55122C8D87C1" ascii //weight: 4
        $x_4_2 = "\\Akl\\kh\\Release\\kh.pdb" ascii //weight: 4
        $x_2_3 = "AKL.006" ascii //weight: 2
        $x_1_4 = "GetKeyboardState" ascii //weight: 1
        $x_1_5 = "SetKeyHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Ardamax_14849_3
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {41 4b 4c 2e 30 30 37 00 48 6f 6f 6b 00 55 6e 68 6f 6f 6b}  //weight: 4, accuracy: High
        $x_2_2 = {41 4b 4c 2e 64 6c 6c 00 41 64 64 4d 6f 6e 69 74 6f 72 65 64 57 6e 64}  //weight: 2, accuracy: High
        $x_2_3 = "Projects\\AKL\\kh" ascii //weight: 2
        $x_1_4 = {53 65 74 4b 65 79 48 6f 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 65 74 57 6e 64 43 61 6c 6c 48 6f 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = "CallNextHookEx" ascii //weight: 1
        $x_1_7 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 00}  //weight: 1, accuracy: High
        $x_1_8 = {49 6e 69 74 69 61 6c 69 7a 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Ardamax_14849_4
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keylogger engine to file" wide //weight: 1
        $x_1_2 = "Keylogger License Warning" wide //weight: 1
        $x_1_3 = "Hidden mode on:" wide //weight: 1
        $x_1_4 = "Keystrokes Log" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_5
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {63 74 73 5c 41 4b 4c 5c 6b 68 5c 52 65 6c 65 61 73 65 5c 6b 68 2e 70 64 62 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {04 00 41 4b 4c 2e 64 6c 6c 00 41 64 64 4d 6f 6e 69 74 6f 72 65 64 57 6e 64 00 43 6c 65 61 72 4b 65 79 48 6f 6f 6b 00}  //weight: 10, accuracy: High
        $x_3_3 = "578CE63E105144C7B9A618DB1CA83FC4" wide //weight: 3
        $x_3_4 = "42D92720215F445B8C2534E8BE51B7C0" wide //weight: 3
        $x_1_5 = "RemoveMonitoredWnd" ascii //weight: 1
        $x_1_6 = "keybd_event" ascii //weight: 1
        $x_1_7 = "MapVirtualKeyW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Ardamax_14849_6
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "AKLMW" wide //weight: 4
        $x_4_2 = "The keylogger will automatically delete itself on" wide //weight: 4
        $x_4_3 = {41 4b 56 2e 65 78 65 00 2e 63 68 6d 00}  //weight: 4, accuracy: High
        $x_1_4 = "Local\\{E3893ABF-53E0-4228-9A27-1C69FB1D67C2}" wide //weight: 1
        $x_1_5 = "Local\\{1BF90DA7-B424-43bf-AEBA-ACE442A4D429}" wide //weight: 1
        $x_1_6 = "Local\\{8761A525-8891-4f1b-85AF-2BC5EB12238A}" wide //weight: 1
        $x_1_7 = "Local\\{0AB1FAA8-7B11-4291-BCCD-6669E8DD17F6}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Ardamax_14849_7
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {3c 2f 62 6f 64 79 3e 3c 2f 68 74 6d 6c 3e 00 00 4c 6f 61 64 69 6e 67 20 4b 65 79 73 74 72 6f 6b 65 73 20 4c 6f 67 2e 2e 2e}  //weight: 10, accuracy: High
        $x_1_2 = "\"%s\" Keystrokes Log file cannot open." ascii //weight: 1
        $x_1_3 = "\"%s\" Keystrokes Log file corrupted." ascii //weight: 1
        $x_1_4 = "Unknown \"%s\" Keystrokes Log file format." ascii //weight: 1
        $x_1_5 = "Filtering Keystrokes Log..." ascii //weight: 1
        $x_1_6 = "Storing Keystrokes Log..." ascii //weight: 1
        $x_1_7 = "Searching logs..." ascii //weight: 1
        $x_1_8 = "Logs not found." ascii //weight: 1
        $x_1_9 = "Loading Screenshots..." ascii //weight: 1
        $x_1_10 = "\"%s\" Screenshots file cannot open." ascii //weight: 1
        $x_1_11 = "\"%s\" Screenshots file corrupted." ascii //weight: 1
        $x_1_12 = "Unknown \"%s\" Screenshots file format." ascii //weight: 1
        $x_1_13 = "Filtering Screenshot" ascii //weight: 1
        $x_1_14 = "<a href=\"scr%i.jpg\"><img src=\"thumb%i.jpg\" border=\"0\" /></a>" ascii //weight: 1
        $x_1_15 = "Storing Screenshots..." ascii //weight: 1
        $x_1_16 = "%s\\scr%i.jpg" ascii //weight: 1
        $x_1_17 = "%s\\thumb%i.jpg" ascii //weight: 1
        $x_1_18 = "Loading Web Log..." ascii //weight: 1
        $x_1_19 = "\"%s\" Web Log file cannot open." ascii //weight: 1
        $x_1_20 = "\"%s\" Web Log file corrupted." ascii //weight: 1
        $x_1_21 = "Unknown \"%s\" Web Log file format." ascii //weight: 1
        $x_1_22 = "Filtering Web Log..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 12 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Ardamax_14849_8
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 03 01 00 00 75 12 8b 41 08 d1 e8 40 8d 71 0c 3b c2}  //weight: 1, accuracy: High
        $x_1_2 = {56 85 c9 74 0b 8b 71 44 3b 35 ?? ?? ?? ?? 74 0c 8b 31 85 f6 74 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_9
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 4b 4c 4d 57 00}  //weight: 2, accuracy: High
        $x_2_2 = {41 4b 4c 2e 30 30 33 00 73 66 78 5f 6d 61 69 6e 00}  //weight: 2, accuracy: High
        $x_2_3 = {55 8b ec 51 51 56 57 68 ?? ?? 00 10 33 ff 57 ff 15 ?? ?? 00 10 3b c7 74 0e 57 57 68 65 80 00 00 50 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_10
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0e 53 53 68 65 80 00 00 50 ff 15 ?? ?? ?? ?? [0-1] 68 ?? ?? ?? ?? be 04 01 00 00 56 ff 15 ?? ?? ?? ?? 8b 4d 08 8b 01 ff (10|50 ??) 53 68 80 00 00 00 6a 03 53 6a 01 68 00 00 00 80 50 ff 15 ?? ?? ?? ?? (a3 ?? ?? ?? ?? 83|83 f8 ff a3 ?? ?? ?? ??) 75 04 33 c0 eb 61 57 53 8d 4d f8 51 6a 04 8d 4d fc 51 50 ff 15 ?? ?? ?? ?? 8b 45 fc 2b c3 bf ?? ?? ?? ?? 74 0d 48 75 12 56 57 ff 15 ?? ?? ?? ?? eb 08 56 57 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? 53 57 ff 15 ?? ?? ?? ?? 5f e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_11
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "UnhookWindowsHookEx" ascii //weight: 2
        $x_2_2 = "SetWindowsHookExA" ascii //weight: 2
        $x_2_3 = "ZwQuerySystemInformation" ascii //weight: 2
        $x_2_4 = {2e 30 30 37 00 48 6f 6f 6b 00 55 6e 68 6f 6f 6b 00}  //weight: 2, accuracy: High
        $x_2_5 = {68 38 20 00 10 68 2c 20 00 10 ff 15 0c 20 00 10 50 ff 15 08 20 00 10 85 c0 a3 08 30 00 10 74 41 6a 00 6a 06 68 18 30 00 10 50 6a ff ff 15 04 20 00 10 6a 00 6a 06 68 10 30 00 10 ff 35 08 30 00 10 c6 05 10 30 00 10 68}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_12
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fa ee c2 99 ea 44 7c 06}  //weight: 1, accuracy: High
        $x_1_2 = {90 90 8b 45 08 a3 04 f0 00 01 a1 94 dc 00 01 85 c0 74 2e 68 04 01 00 00 ff 75 0c 68 08 f0 00 01 ff d0 a1 9c dc 00 01 85 c0 74 16 6a 00 ff 35 78 dc 00 01 68 0d 2f 00 01 6a 04 ff d0 a3 00 f0 00 01 90 90}  //weight: 1, accuracy: High
        $x_1_3 = {be 1a 00 00 80 eb 32 85 c0 7c 34 53 57 e8 23 ff ff ff 59 59 85 c0 75 03 ff 45 f8}  //weight: 1, accuracy: High
        $x_1_4 = {90 90 33 c0 ba 38 a1 00 01 39 45 08 75 0b 8b 4d 0c 8b 41 08 8d 51 0c eb 0f 83 7d 08 01 75 18 8b 45 0c 8d 50 14 8b 40 10 d1 e8 40 3d 03 01 00 00 72 05 b8 04 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_13
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "UnhookWindowsHookEx" ascii //weight: 2
        $x_2_2 = "SetWindowsHookExA" ascii //weight: 2
        $x_2_3 = "ZwQuerySystemInformation" ascii //weight: 2
        $x_2_4 = {2e 30 30 37 00 48 6f 6f 6b 00 55 6e 68 6f 6f 6b 00}  //weight: 2, accuracy: High
        $x_2_5 = {68 48 20 00 10 68 3c 20 00 10 ff 15 14 20 00 10 50 ff 15 10 20 00 10 85 c0 a3 34 30 00 10 74 5b 56 be 14 30 00 10 56 ff 15 08 20 00 10 6a 00 6a 06 68 2c 30 00 10 ff 35 34 30 00 10 6a ff ff 15 0c 20 00 10 6a 00 6a 06 68 0c 30 00 10 ff 35 34 30 00 10 [0-48] c6 05 0c 30 00 10 68}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_14
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "UnhookWindowsHookEx" ascii //weight: 2
        $x_2_2 = "SetWindowsHookExA" ascii //weight: 2
        $x_2_3 = "ZwQuerySystemInformation" ascii //weight: 2
        $x_2_4 = {2e 30 30 37 00 48 6f 6f 6b 00 55 6e 68 6f 6f 6b 00}  //weight: 2, accuracy: High
        $x_2_5 = {68 4c 20 00 10 68 40 20 00 10 ff 15 18 20 00 10 50 ff 15 14 20 00 10 85 c0 a3 34 30 00 10 74 5d 56 be 14 30 00 10 56 ff 15 08 20 00 10 6a 00 6a 06 68 2c 30 00 10 ff 35 34 30 00 10 6a ff ff 15 10 20 00 10 6a 00 6a 06 68 0c 30 00 10 ff 35 34 30 00 10 [0-48] c6 05 0c 30 00 10 68}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_15
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 00 00 00 00 41 4b 4c 2e 30 30 33 00 73 66 78 5f 6d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_2 = {23 00 00 00 00 41 4b 4c 2e 30 30 33 00 73 66 78 5f 6d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 32 00 38 00 34 00 36 00 33 00 5c 00 00 00 41 00 4b 00 4c 00 4d 00 57 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 53 00 79 00 73 00 33 00 32 00 5c 00 00 00 41 00 4b 00 4c 00 4d 00 57 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 57 00 f4 01 47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 57 00 00 d6 01 47 65 74 54 65 6d 70 50 61 74 68 57 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "ShellExecuteW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_16
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $n_100_1 = ".?AVCPasswordEnterDlg@@" ascii //weight: -100
        $x_1_2 = {fa ee c2 99 ea 44 7c 06}  //weight: 1, accuracy: High
        $x_1_3 = {ff 76 04 ff 36 ff 75 08 e8 ?? ?? ?? ?? 83 c4 0c ff 76 04 8b ce ff 75 08 e8 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 5e 5d c2 04 00}  //weight: 1, accuracy: Low
        $x_1_4 = {90 90 8b 7d 0c 8b 4d 08 8d 45 fc 50 be 9d 00 00 00 56 57 e8 d2 fe ff ff 85 c0 7c 1e 39 75 fc 75 19 ff 37 e8 e9 fe ff ff 59 3b 47 04 75 0c 57 e8 1e ff ff ff 33 c0 59 40 eb 0a}  //weight: 1, accuracy: High
        $x_1_5 = {90 90 33 d2 33 f6 39 55 0c 7e 19 83 fa 04 72 02 33 d2 8b 45 08 8a 4c 17 08 03 c6 30 08 42 46 3b 75 0c 7c e7 90 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_17
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ARDAMAX KEYLOGGER IS DISTRIBUTED \"AS IS\"" ascii //weight: 1
        $x_1_2 = "http://www.ardamax.com/keylogger/" ascii //weight: 1
        $x_1_3 = {22 6c 7a 6d 61 2e 65 78 65 22 20 22 64 22 20 22 ?? 2e 6c 7a 22 20 22 (41|52) 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_4 = "\\Ardamax Keylogger" ascii //weight: 1
        $x_1_5 = "\\Log Viewer.lnk" ascii //weight: 1
        $x_1_6 = {4b 65 79 6c 6f 67 67 65 72 20 45 6e 67 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {41 4b 4c 4d 57 00 53 65 74 75 70 20 68 61 73 20 64 65 74 65 63 74 65 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_18
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fa ee c2 99 ea 44 7c 06}  //weight: 1, accuracy: High
        $x_1_2 = {90 90 33 c9 33 f6 39 4d 10 7e 1b 83 f9 0b 7c 02 33 c9 8b 45 0c 8b 55 08 8a 14 11 03 c6 30 10 41 46 3b 75 10 7c e5 90 90}  //weight: 1, accuracy: High
        $x_1_3 = {8d 44 00 01 85 c0 7e 1d 8b d0 56 33 c9 8b 45 08 8d 04 48 be 34 92 00 00 66 31 30 41 83 f9 32 7c ec 4a 75 e7 5e 5d c3}  //weight: 1, accuracy: High
        $x_1_4 = {46 46 50 66 8b 46 44 66 03 85 ?? ?? ff ff 0f b7 c0 50 53 ff 15 ?? ?? ?? ?? 89 85 e4 fd ff ff 3b c3 0f 84 ?? ?? 00 00 50 53 ff 15 ?? ?? ?? ?? 3b c3 0f 84 cb 01 00 00 50 ff 15 ?? ?? ?? ?? 89 85 ?? ?? ff ff 3b c3 0f 84 ?? ?? 00 00 ff b5 ?? ?? ff ff 53 ff 15 ?? ?? ?? ?? 03 f8 89 85 ?? ?? ff ff 57 39 9d ?? ?? ff ff 74 0e ff b5 ?? ?? ff ff e8 ?? ?? ?? ?? 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_19
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {55 8b ec 83 7d 08 00 75 16 f7 45 10 00 00 00 80 75 0d ff 75 10 ff 75 0c e8 ?? ?? ?? ?? 59 59 ff 75 10 ff 75 0c ff 75 08 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 5d c2 0c 00}  //weight: 3, accuracy: Low
        $x_1_2 = "d:\\Projects\\AKL\\kh\\Release\\kh.pdb" ascii //weight: 1
        $x_1_3 = "SetWndMonHook" ascii //weight: 1
        $x_1_4 = "AddMonitoredWnd" ascii //weight: 1
        $x_1_5 = "ClearKeyHook" ascii //weight: 1
        $x_1_6 = "ClearWndMonHook" ascii //weight: 1
        $x_1_7 = "RemoveMonitoredWnd" ascii //weight: 1
        $x_2_8 = "SetKeyHook" ascii //weight: 2
        $x_1_9 = "UWM_WNDMONHOOK_MSG" ascii //weight: 1
        $x_3_10 = "UWM_KEYHOOK_MSG-968C3043-1128-43dc-83A9-55122C8D87C1" ascii //weight: 3
        $x_1_11 = "AKL.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Ardamax_14849_20
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "211"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fa ee c2 99 ea 44 7c 06}  //weight: 10, accuracy: High
        $x_10_2 = {ef 6f c4 0b ff c5 7a 94}  //weight: 10, accuracy: High
        $x_10_3 = {f8 cc e2 99 e8 66 5c 06}  //weight: 10, accuracy: High
        $x_10_4 = {10 aa 6e a9 eb be c0 d8}  //weight: 10, accuracy: High
        $x_10_5 = {40 b7 d8 5a fb 6e af 4a}  //weight: 10, accuracy: High
        $x_100_6 = {8a 54 0d fc 03 c6 30 10 41 46 3b 75 0c 72 e7 5e c9 c2 08 00 1f 00 55 8b ec 51 56 33 c9 33 f6 c7 45 fc ?? ?? ?? ?? 39 4d 0c 76 19 83 f9 04 72 02 33 c9 8b 45 08}  //weight: 100, accuracy: Low
        $x_100_7 = {03 d0 83 c0 08 89 55 f8 3b c2 eb 3d 0f b7 00 8b d0 81 e2 ff 0f 00 00 03 d7 3b 55 08 72 23 3b 55 0c 73 1e 25 00 f0 00 00 bb 00 30 00 00 66 3b c3 75 0f 83 7d 10 00 8b 41 04 74 04 01 02 eb 02 29 02 8b 45 fc 40 40 3b 45 f8}  //weight: 100, accuracy: High
        $x_1_8 = {46 46 50 66 8b 46 44 66 03 85 ?? ?? ff ff 0f b7 c0 50 53 ff 15 ?? ?? ?? ?? 89 85 e4 fd ff ff 3b c3 0f 84 ?? ?? 00 00 50 53 ff 15 ?? ?? ?? ?? 3b c3 0f 84 cb 01 00 00 50 ff 15 ?? ?? ?? ?? 89 85 ?? ?? ff ff 3b c3 0f 84 ?? ?? 00 00 ff b5 ?? ?? ff ff 53 ff 15 ?? ?? ?? ?? 03 f8 89 85 ?? ?? ff ff 57 39 9d ?? ?? ff ff 74 0e ff b5 ?? ?? ff ff e8 ?? ?? ?? ?? 59}  //weight: 1, accuracy: Low
        $x_1_9 = {74 2e 68 04 01 00 00 ff 75 0c 68 ?? ?? ?? 01 ff d0 a1 ?? ?? ?? 01 85 c0 74 16 6a 00 ff 35 ?? ?? ?? 01 68 ?? ?? ?? 01 6a 04 ff d0 a3 ?? ?? ?? 01 90 90 11 00 90 90 8b 45 08 a3 ?? ?? ?? 01 a1 ?? ?? ?? 01 85 c0}  //weight: 1, accuracy: Low
        $x_1_10 = {71 0c 6a 02 eb 05 ff 71 0c 6a 01 ff 35 ?? ?? ?? 01 ff 35 ?? ?? ?? 01 ff 15 ?? ?? ?? 01 90 90 0f 00 90 90 8b 4d 08 8b 41 08 48 74 0a 48 75 1e ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Ardamax_14849_21
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AllPeriod" ascii //weight: 1
        $x_1_2 = "\"%s\" Keystrokes Log file cannot open." ascii //weight: 1
        $x_1_3 = "\"%s\" Keystrokes Log file corrupted." ascii //weight: 1
        $x_1_4 = "\"%s\" Web Log file cannot open." ascii //weight: 1
        $x_1_5 = "\"%s\" Web Log file corrupted." ascii //weight: 1
        $x_1_6 = "HTML File (*.htm)" ascii //weight: 1
        $x_1_7 = "Keystrokes Log" ascii //weight: 1
        $x_1_8 = "KeysView" ascii //weight: 1
        $x_1_9 = "Log Viewer" ascii //weight: 1
        $x_1_10 = "Logs not found." ascii //weight: 1
        $x_1_11 = "No password entered." ascii //weight: 1
        $x_1_12 = "No records found" ascii //weight: 1
        $x_1_13 = "Page Title" ascii //weight: 1
        $x_1_14 = "PageTitleLen" ascii //weight: 1
        $x_1_15 = "Password is not valid." ascii //weight: 1
        $x_1_16 = "Select a record to view from the list above." ascii //weight: 1
        $x_1_17 = "Select the folder with the logs." ascii //weight: 1
        $x_1_18 = "Storing Keystrokes Log..." ascii //weight: 1
        $x_1_19 = "Storing Web Log..." ascii //weight: 1
        $x_1_20 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_21 = "Unknown \"%s\" Keystrokes Log file format." ascii //weight: 1
        $x_1_22 = "Unknown \"%s\" Web Log file format." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_22
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "10C88BB1E3294978B96BBF7D881568CC" ascii //weight: 5
        $x_2_2 = "Storing Chattrokes Log..." wide //weight: 2
        $x_2_3 = "Loading Keystrokes Log..." wide //weight: 2
        $x_2_4 = "\"%s\" Keystrokes Log file cannot open." wide //weight: 2
        $x_2_5 = "\"%s\" Keystrokes Log file corrupted." wide //weight: 2
        $x_2_6 = "Unknown \"%s\" Keystrokes Log file format." wide //weight: 2
        $x_2_7 = "Filtering Keystrokes Log..." wide //weight: 2
        $x_2_8 = "Storing Keystrokes Log..." wide //weight: 2
        $x_2_9 = "Loading Web Log..." wide //weight: 2
        $x_2_10 = "\"%s\" Web Log file cannot open." wide //weight: 2
        $x_2_11 = "\"%s\" Web Log file corrupted." wide //weight: 2
        $x_2_12 = "Unknown \"%s\" Web Log file format." wide //weight: 2
        $x_2_13 = "Filtering Web Log..." wide //weight: 2
        $x_2_14 = "Storing Web Log..." wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_23
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Password is not valid." ascii //weight: 1
        $x_1_2 = "No password entered." ascii //weight: 1
        $x_1_3 = "Password protection (Security Page) is not active." ascii //weight: 1
        $x_1_4 = "When someone clicks \"%s\"," ascii //weight: 1
        $x_1_5 = "No method for sending logs is selected." ascii //weight: 1
        $x_1_6 = "You have %i day(s) left" ascii //weight: 1
        $x_1_7 = "The Ardamax Keylogger test FTP delivery has been completed succesfully." ascii //weight: 1
        $x_1_8 = "The Ardamax Keylogger test e-mail delivery has been completed succesfully." ascii //weight: 1
        $x_1_9 = "The \"Launch at Windows startup\" option (Options Page) is disabled. The keylogger will not be launched when Windows is started." ascii //weight: 1
        $x_1_10 = "This is a test of the Ardamax Keylogger." ascii //weight: 1
        $x_1_11 = "UWM_KEYHOOK_MSG-968C3043-1128-43dc-83A9-55122C8D87C1" ascii //weight: 1
        $x_1_12 = "AKLMW" ascii //weight: 1
        $x_1_13 = "{1BF90DA7-B424-43bf-AEBA-ACE442A4D429}" ascii //weight: 1
        $x_1_14 = "The \"Hide the program from Windows startup list\" option is enabled (Invisibility Page). If the computer is not shut down correctly or if there is a system failure, the keylogger will not be started together with Windows." ascii //weight: 1
        $x_1_15 = "ClearKeyHook" ascii //weight: 1
        $x_1_16 = "SetKeyHook" ascii //weight: 1
        $x_1_17 = "http://www.ardamax.com" ascii //weight: 1
        $x_1_18 = "Ardamax Keylogger" ascii //weight: 1
        $x_1_19 = "AKL_TEST" ascii //weight: 1
        $x_1_20 = ".001_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (18 of ($x*))
}

rule MonitoringTool_Win32_Ardamax_14849_24
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax"
        threat_id = "14849"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Engine Builder" ascii //weight: 1
        $x_2_2 = "Executable name is required." ascii //weight: 2
        $x_2_3 = "When someone clicks \"%s\", " ascii //weight: 2
        $x_2_4 = "will be invisibly installed. " ascii //weight: 2
        $x_2_5 = "It will start launching " ascii //weight: 2
        $x_2_6 = "invisible in the system tray" ascii //weight: 2
        $x_3_7 = "Each %i %s it will send logs to \"%s\" via e-mail. " ascii //weight: 3
        $x_3_8 = "Each %i %s it will upload logs to the \"%s\" folder on the FTP server \"%s\". " ascii //weight: 3
        $x_2_9 = "To restore Visible Mode press:" ascii //weight: 2
        $x_2_10 = "Deployment package created succes" ascii //weight: 2
        $x_2_11 = "To enable/disable the invisible mode, the \"" ascii //weight: 2
        $x_2_12 = "will automatically delete itself on " ascii //weight: 2
        $x_3_13 = "Each time the installation package is launched, it will display the reminder that you should register it." ascii //weight: 3
        $x_3_14 = "The \"Launch at Windows startup\" option (Options Page) is disabled. The " ascii //weight: 3
        $x_2_15 = "Password protection (Security Page) is not active." ascii //weight: 2
        $x_3_16 = "You have %i day(s) left" ascii //weight: 3
        $x_5_17 = "UWM_WNDMONHOOK_MSG-" ascii //weight: 5
        $x_5_18 = "UWM_KEYHOOK_MSG-" ascii //weight: 5
        $x_5_19 = "www.ardamax.com" ascii //weight: 5
        $x_4_20 = "Ardamax Keylogger" ascii //weight: 4
        $x_5_21 = "AKL_TEST/test" ascii //weight: 5
        $x_3_22 = "AKL_TEST" ascii //weight: 3
        $x_2_23 = "Cannot launch Log Viewer." ascii //weight: 2
        $x_3_24 = "Are you sure to clear" ascii //weight: 3
        $x_4_25 = "Instant.LoggingEnabled" ascii //weight: 4
        $x_2_26 = "Security.ProtectHiddenMode" ascii //weight: 2
        $x_2_27 = "Invisibility.UninstallLis" ascii //weight: 2
        $x_2_28 = "Options.HideOnStartup" ascii //weight: 2
        $x_2_29 = "Options.HideHotkey" ascii //weight: 2
        $x_3_30 = "test FTP delivery has been completed succesfully." ascii //weight: 3
        $x_3_31 = "test e-mail delivery has been completed succesfully." ascii //weight: 3
        $x_4_32 = "/order_akl.html" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((14 of ($x_2_*))) or
            ((1 of ($x_3_*) and 12 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 13 of ($x_2_*))) or
            ((2 of ($x_3_*) and 11 of ($x_2_*))) or
            ((3 of ($x_3_*) and 9 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 10 of ($x_2_*))) or
            ((4 of ($x_3_*) and 8 of ($x_2_*))) or
            ((5 of ($x_3_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_3_*) and 7 of ($x_2_*))) or
            ((6 of ($x_3_*) and 5 of ($x_2_*))) or
            ((7 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_3_*) and 4 of ($x_2_*))) or
            ((8 of ($x_3_*) and 2 of ($x_2_*))) or
            ((9 of ($x_3_*) and 1 of ($x_1_*))) or
            ((9 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 12 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 10 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 11 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 8 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_4_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 6 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 7 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 7 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 8 of ($x_3_*))) or
            ((2 of ($x_4_*) and 10 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((2 of ($x_4_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 6 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 7 of ($x_3_*))) or
            ((3 of ($x_4_*) and 8 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_4_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_4_*) and 5 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 5 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_4_*) and 6 of ($x_3_*))) or
            ((1 of ($x_5_*) and 11 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 12 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 10 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 6 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 6 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 7 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 8 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 9 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 10 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 8 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 5 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 4 of ($x_3_*))) or
            ((2 of ($x_5_*) and 9 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 8 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 6 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 6 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 7 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_3_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*))) or
            ((3 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 7 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 5 of ($x_3_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((3 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((4 of ($x_5_*) and 4 of ($x_2_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*))) or
            ((4 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((4 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((4 of ($x_5_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Ardamax_A_259768_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Ardamax.A!MSR"
        threat_id = "259768"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keyloggers.ro Distribution" wide //weight: 1
        $x_1_2 = "keylogger viewer" wide //weight: 1
        $x_1_3 = "msnmsgr.exe" wide //weight: 1
        $x_10_4 = "ardamax" wide //weight: 10
        $x_1_5 = "unhookwindowshookex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

