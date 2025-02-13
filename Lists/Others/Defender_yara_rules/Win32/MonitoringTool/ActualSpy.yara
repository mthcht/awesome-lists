rule MonitoringTool_Win32_ActualSpy_14895_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/ActualSpy"
        threat_id = "14895"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ActualSpy"
        severity = "22"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ctrl+Alt+Shift+F8" ascii //weight: 2
        $x_2_2 = "actualspyrep@gmail.com" ascii //weight: 2
        $x_2_3 = "support@actualspy" ascii //weight: 2
        $x_2_4 = "ftp.actualspy.com" ascii //weight: 2
        $x_2_5 = "DirMonitor" ascii //weight: 2
        $x_1_6 = "Actual Spy" ascii //weight: 1
        $x_1_7 = "Software\\AKMonitor\\" ascii //weight: 1
        $x_1_8 = "Software\\ASMon\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_ActualSpy_14895_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/ActualSpy"
        threat_id = "14895"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ActualSpy"
        severity = "22"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 68 70 72 6f 67 2e 64 6c 6c 00 48 69 64 65 [0-1] 50 72 6f 63 65 73 73 00 53 68 6f 77 50 72 6f 63 65 73 73}  //weight: 1, accuracy: Low
        $x_1_2 = "nthidefilemapping" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_ActualSpy_14895_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/ActualSpy"
        threat_id = "14895"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ActualSpy"
        severity = "22"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SetKeyboardHook" ascii //weight: 1
        $x_1_2 = {75 23 f7 c3 00 00 00 80 75 1b 83 ff 10 75 16 56 6a 01 68 13 2b 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "apphook" ascii //weight: 1
        $x_1_4 = "mousehook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_ActualSpy_14895_3
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/ActualSpy"
        threat_id = "14895"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ActualSpy"
        severity = "22"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 6b 64 6c 6c 2e 64 6c 6c 00 52 65 6d 6f 76 65 41 70 70 48 6f 6f 6b}  //weight: 1, accuracy: High
        $x_1_2 = "from hookdll.dll" ascii //weight: 1
        $x_1_3 = "Software\\Borland\\Locales" ascii //weight: 1
        $x_1_4 = "SetKeyboardHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_ActualSpy_14895_4
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/ActualSpy"
        threat_id = "14895"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ActualSpy"
        severity = "22"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\AKProgram\\Keylogger" ascii //weight: 1
        $x_1_2 = "spy_only_char" ascii //weight: 1
        $x_1_3 = "to show Actual Keylogger" ascii //weight: 1
        $x_1_4 = "Actual Keylogger_is" ascii //weight: 1
        $x_1_5 = "Actual Spy - " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule MonitoringTool_Win32_ActualSpy_14895_5
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/ActualSpy"
        threat_id = "14895"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ActualSpy"
        severity = "22"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KeyMMF" ascii //weight: 2
        $x_1_2 = "AppHook" ascii //weight: 1
        $x_1_3 = "DestroyHook" ascii //weight: 1
        $x_1_4 = "KeyboardHook" ascii //weight: 1
        $x_1_5 = "MouseHook" ascii //weight: 1
        $x_1_6 = "ShiftCapsHook" ascii //weight: 1
        $x_1_7 = "WindowHook" ascii //weight: 1
        $x_1_8 = "newnew" ascii //weight: 1
        $x_3_9 = {74 2f 6a 38 6a 00 6a 00 68 1f 00 0f 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

