rule MonitoringTool_Win32_Spector_11498_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Spector"
        threat_id = "11498"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Spector"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "spector" ascii //weight: 10
        $x_1_2 = "HelpStartRecord" ascii //weight: 1
        $x_1_3 = "HelpStopRecord" ascii //weight: 1
        $x_1_4 = "HelpStopHook" ascii //weight: 1
        $x_1_5 = "HelpSetHook" ascii //weight: 1
        $x_1_6 = "StartInternet" ascii //weight: 1
        $x_1_7 = "StopInternet" ascii //weight: 1
        $x_1_8 = "MonitorDCEEvents" ascii //weight: 1
        $x_1_9 = "InactivityTimerProc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Spector_11498_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Spector"
        threat_id = "11498"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Spector"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CB8DE863-0561-4ffd-9B86-5BA2E941BA52" ascii //weight: 10
        $x_10_2 = "\\.\\PhysicalDrive%d" ascii //weight: 10
        $x_1_3 = {53 4d 54 50 50 4f 50 00 57 65 62 4d 61 69 6c 00 50 6c 61 69 6e 54 65 78 74}  //weight: 1, accuracy: High
        $x_1_4 = "StartRecordingWithWindows" ascii //weight: 1
        $x_1_5 = "TakeKeywordScreenshot" ascii //weight: 1
        $x_1_6 = "AgentSettings.CaptureKeyStrokes" ascii //weight: 1
        $x_1_7 = "SetFileTimeToKernels_Path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Spector_11498_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Spector"
        threat_id = "11498"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Spector"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "CheckDocAOL:GetAddresses" ascii //weight: 3
        $x_2_2 = "%22action%22%3A%22SendMessage%22" ascii //weight: 2
        $x_3_3 = "CheckDocGMail:CheckDocEmail" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Spector_11498_3
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Spector"
        threat_id = "11498"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Spector"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 61 6e 74 50 4f 53 54 47 4d 61 69 6c [0-48] 6d 61 69 6c 2e 67 6f 6f 67 6c 65 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_2 = {57 61 6e 74 50 4f 53 54 4f 57 41 [0-48] 2f 6f 77 61 2f 61 75 74 68 2f 6f 77 61 61 75 74 68 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {57 61 6e 74 50 4f 53 54 59 61 68 6f 6f [0-48] 6d 61 69 6c 2e 79 61 68 6f 6f 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 6e 64 4d 65 73 73 61 67 65 00 61 63 74 69 6f 6e 00 00 72 65 71 75 65 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Spector_11498_4
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Spector"
        threat_id = "11498"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Spector"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 [0-48] 49 41 6c 6c 6f 63 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 6f 74 4d 61 69 6c 00 59 61 68 6f 6f 00 00 00 53 65 6e 64 00 00 00 00 52 65 63 65 69 76 65 00 6e 63 61 6c 72 70 63 00 25 73 5f 25 73 5f 25 64 00 00 00 00 74 69 64 70 69 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 74 61 72 74 52 65 63 6f 72 64 00 53 74 6f 70 52 65 63 6f 72 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Spector_11498_5
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Spector"
        threat_id = "11498"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Spector"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Phillip--GtVerfyStng--Powers" ascii //weight: 1
        $x_1_2 = "ProcessKeystrokeFile1" ascii //weight: 1
        $x_1_3 = "SetFileTimeToKernels_Handle" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Spector_11498_6
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Spector"
        threat_id = "11498"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Spector"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Recorder::ChatAdd" ascii //weight: 2
        $x_3_2 = "ProcessChatEvent: Process data not found for process 0x%p" ascii //weight: 3
        $x_2_3 = "ProcessPortEvent: Process data not found for process 0x%p" ascii //weight: 2
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Spector_11498_7
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Spector"
        threat_id = "11498"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Spector"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "msnetpackettype" ascii //weight: 10
        $x_10_2 = "spector" ascii //weight: 10
        $x_1_3 = {53 74 61 72 74 52 65 63 6f 72 64 00 53 74 6f 70 52 65 63 6f 72 64 00}  //weight: 1, accuracy: High
        $x_1_4 = "--GtVerfyStng--" ascii //weight: 1
        $x_1_5 = "AgentSettings.CaptureKeyStrokes" ascii //weight: 1
        $x_1_6 = "StartRecordingWithWindows" ascii //weight: 1
        $x_1_7 = "TakeKeywordScreenshot" ascii //weight: 1
        $x_1_8 = "stealth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Spector_11498_8
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Spector"
        threat_id = "11498"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Spector"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {84 c9 75 f6 66 8b 0d ?? ?? ?? ?? 66 89 08 8a 15 ?? ?? ?? ?? 88 50 02 8b 07 56 8b cf 8b 50 0c ff d2 6a 02 6a 00 6a 00 8b 5d e4 53 ff 15 ?? ?? ?? ?? 8b c6 8d 48 01}  //weight: 4, accuracy: Low
        $x_4_2 = {05 d8 22 00 00 50 ff 15 ?? ?? ?? ?? 89 86 dc 01 00 00 3b c3 74 ?? 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 89 86 ?? ?? ?? ?? 8d be ?? ?? ?? ?? 57 68 46 23 00 00 6a 01 68 23 56 14 23 ff d0}  //weight: 4, accuracy: Low
        $x_1_3 = "webloccheck" ascii //weight: 1
        $x_1_4 = "--GtVerfyStng--" ascii //weight: 1
        $x_1_5 = "msnetpackettype" ascii //weight: 1
        $x_1_6 = "weblocaolse" ascii //weight: 1
        $x_1_7 = "wowskype" ascii //weight: 1
        $x_1_8 = "kbdwdmdev" ascii //weight: 1
        $x_1_9 = "webmapibox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Spector_11498_9
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Spector"
        threat_id = "11498"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Spector"
        severity = "17"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 41 43 45 42 4f 4f 4b 5f 48 54 54 50 00 [0-6] 42 4f 4e 4a 4f 55 52 00 [0-6] 4d 59 53 50 41 43 45 5f 48 54 54 50}  //weight: 1, accuracy: Low
        $x_1_2 = {49 43 51 5f 48 4c 00 [0-6] 41 49 4d 5f 4d 45 45 42 4f 00 [0-6] 59 41 48 4f 4f 5f 4d 45 45 42 4f 00 [0-5] 47 54 41 4c 4b 5f 4d 45 45 42 4f 00 [0-6] 4d 53 4e 5f 4d 45 45 42 4f 00 [0-6] 49 43 51 5f 4d 45 45 42 4f 00 [0-6] 4a 41 42 42 45 52 5f 4d 45 45 42 4f 00 [0-6] 55 4e 4b 4e 4f 57 4e 5f 4d 45 45 42 4f}  //weight: 1, accuracy: Low
        $x_1_3 = {41 73 74 72 61 5f 54 72 69 6c 6c 69 61 6e 00 [0-6] 41 49 4d 5f 54 72 69 6c 6c 69 61 6e 00 [0-6] 46 61 63 65 62 6f 6f 6b 5f 54 72 69 6c 6c 69 61 6e 00 [0-6] 47 54 74 61 6c 6b 5f 54 72 69 6c 6c 69 61 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {45 4e 44 5f 53 45 53 53 49 4f 4e 00 [0-6] 53 54 41 52 54 5f 41 43 54 49 56 49 54 59 00 [0-6] 45 4e 44 5f 41 43 54 49 56 49 54 59 00 [0-6] 53 54 41 52 54 5f 49 4e 41 43 54 49 56 49 54 59}  //weight: 1, accuracy: Low
        $x_1_5 = "Calling TermClient from ServiceSpector::Reinitialize" ascii //weight: 1
        $x_1_6 = "\\\\.\\pipe\\SpectorLiveLog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

