rule HackTool_Win32_Wpakill_B_2147634461_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Wpakill.B"
        threat_id = "2147634461"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Wpakill"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\SysWOW64\\slwga.dll" wide //weight: 1
        $x_1_2 = "\\SysWOW64\\slmgr.vbs" wide //weight: 1
        $x_1_3 = "\\System32\\systemcpl.dll" wide //weight: 1
        $x_1_4 = "\\System32\\sppuinotify.dll" wide //weight: 1
        $x_1_5 = "RemoveWAT" wide //weight: 1
        $x_1_6 = "sc create antiwlmssvc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Wpakill_C_2147634462_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Wpakill.C"
        threat_id = "2147634462"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Wpakill"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chew-WGA" ascii //weight: 1
        $x_1_2 = "<Run>autorun.exe</Run>" ascii //weight: 1
        $x_1_3 = "<pid>BD6B319C-8778-4BB7-A156-ECB70E621174</pid>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

