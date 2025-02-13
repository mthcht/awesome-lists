rule HackTool_Win32_TaskSchedulerQakBot_A_2147813262_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/TaskSchedulerQakBot.A"
        threat_id = "2147813262"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "TaskSchedulerQakBot"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe" wide //weight: 1
        $x_1_2 = "/create" wide //weight: 1
        $x_1_3 = "nt authority\\system" wide //weight: 1
        $x_1_4 = "/tn" wide //weight: 1
        $x_1_5 = "/tr" wide //weight: 1
        $x_1_6 = "/sc once /z /st" wide //weight: 1
        $x_1_7 = "/et" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

