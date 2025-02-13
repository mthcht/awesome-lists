rule HackTool_Win32_WMIShell_A_2147643576_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/WMIShell.A"
        threat_id = "2147643576"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "WMIShell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "81"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {50 83 c7 0b 6a 40 6a 03 57 56 ff d3}  //weight: 10, accuracy: High
        $x_10_2 = "VirtualProtectEx" ascii //weight: 10
        $x_10_3 = "WriteProcessMemory" ascii //weight: 10
        $x_10_4 = "LookupAccountSidA" ascii //weight: 10
        $x_10_5 = "DuplicateTokenEx" ascii //weight: 10
        $x_10_6 = "wmiprvse.exe" ascii //weight: 10
        $x_10_7 = "{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}" ascii //weight: 10
        $x_10_8 = "WinSta0\\Default" ascii //weight: 10
        $x_1_9 = "/xxoo/-->Got WMI process Pid: %d" ascii //weight: 1
        $x_1_10 = "/xxoo/-->This exploit gives you a Local System shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

