rule Trojan_Win32_SuspScheduled_A_2147955554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspScheduled.A"
        threat_id = "2147955554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspScheduled"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" ascii //weight: 1
        $x_1_2 = "New-ScheduledTaskTrigger -At" ascii //weight: 1
        $x_1_3 = "-Once;" ascii //weight: 1
        $x_1_4 = "New-ScheduledTaskAction -Execute" ascii //weight: 1
        $x_1_5 = "ClientUpdate.ps1" ascii //weight: 1
        $x_1_6 = "New-ScheduledTaskSettingsSet;" ascii //weight: 1
        $x_1_7 = "-RunLevel Highest" ascii //weight: 1
        $x_1_8 = "-Force" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

