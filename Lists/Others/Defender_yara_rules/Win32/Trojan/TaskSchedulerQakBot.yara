rule Trojan_Win32_TaskSchedulerQakBot_B_2147826517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TaskSchedulerQakBot.B"
        threat_id = "2147826517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TaskSchedulerQakBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe" wide //weight: 1
        $x_1_2 = "/create" wide //weight: 1
        $x_1_3 = "nt authority\\system" wide //weight: 1
        $x_1_4 = "/tn" wide //weight: 1
        $x_1_5 = "/tr" wide //weight: 1
        $x_1_6 = "/sc once" wide //weight: 1
        $x_1_7 = "/et" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

