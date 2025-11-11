rule Trojan_Win32_SusSchTasks_SP_2147957215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusSchTasks.SP!MTB"
        threat_id = "2147957215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusSchTasks"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "NoProfile" wide //weight: 1
        $x_1_3 = "Start-ScheduledTask" wide //weight: 1
        $x_1_4 = "StateRepositorys" wide //weight: 1
        $x_1_5 = "TaskName" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

