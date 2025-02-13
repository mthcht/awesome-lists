rule MonitoringTool_Win32_PowerSpy_147221_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PowerSpy"
        threat_id = "147221"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerSpy"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{Scroll Lock}" wide //weight: 1
        $x_1_2 = "Insert Into WinCaps (Username, Content) Values('" wide //weight: 1
        $x_1_3 = "eMatrixSoft Power Spy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_PowerSpy_147221_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PowerSpy"
        threat_id = "147221"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerSpy"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 65 00 6d 00 78 00 66 00 69 00 6c 00 65 00 2e 00 65 00 6d 00 78 00 [0-32] 69 00 6e 00 69 00 2e 00 69 00 6e 00 69 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 65 8d 45 ?? 50 ff d6 6a 6d 8d ?? ?? ?? ?? ?? 51 ff d6 6a 78 8d ?? ?? ?? ?? ?? 52 ff d6 6a 70 8d ?? ?? ?? ?? ?? 50 ff d6 6a 73 8d ?? ?? ?? ?? ?? 51 ff d6 6a 74 8d ?? ?? ?? ?? ?? 52 ff d6 6a 6d 8d ?? ?? ?? ?? ?? 50 ff d6 6a 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_PowerSpy_147221_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PowerSpy"
        threat_id = "147221"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerSpy"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Buy it Online: www.ematrixsoft.com/buy.html" wide //weight: 1
        $x_1_2 = {61 00 70 00 70 00 69 00 6e 00 69 00 2e 00 69 00 6e 00 69 00 [0-32] 75 00 73 00 72 00 2e 00 69 00 6e 00 69 00 [0-32] 5c 00 65 00 6d 00 78 00 66 00 69 00 6c 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {63 00 6c 00 64 00 72 00 44 00 61 00 74 00 65 00 3d 00 23 00 [0-32] 5c 00 65 00 6d 00 78 00 70 00 73 00 74 00 6d 00 70 00 66 00 69 00 6c 00 65 00 2e 00 65 00 6d 00 78 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_PowerSpy_147221_3
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PowerSpy"
        threat_id = "147221"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerSpy"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Delete * From KeyStrokes" wide //weight: 2
        $x_2_2 = "Do you want to delete all logs before uninstalling the software?" wide //weight: 2
        $x_3_3 = "the 'Send logs to your emailbox' checkbox and retry it after" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_PowerSpy_147221_4
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PowerSpy"
        threat_id = "147221"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerSpy"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "It only demonstrates how the email function works. After you buy and unlock" wide //weight: 3
        $x_3_2 = "NOTE: Due to the limitation of unregistered version, the file attached is a" wide //weight: 3
        $x_1_3 = "Sending Report..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

