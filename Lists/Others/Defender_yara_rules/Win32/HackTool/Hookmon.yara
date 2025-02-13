rule HackTool_Win32_Hookmon_S_2147730428_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Hookmon.S"
        threat_id = "2147730428"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Hookmon"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hook can NOT be Stoped" ascii //weight: 1
        $x_1_2 = "DLL is loaded" ascii //weight: 1
        $x_1_3 = "{62C4CCEB-4D2F-4DE8-86D5-3B5F5149E3C3}" ascii //weight: 1
        $x_1_4 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

