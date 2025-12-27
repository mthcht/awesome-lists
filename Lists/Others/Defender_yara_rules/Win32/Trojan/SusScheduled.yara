rule Trojan_Win32_SusScheduled_A_2147954089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusScheduled.A"
        threat_id = "2147954089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusScheduled"
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
        $n_1_9 = "9453e881-26a8-4973-ba2e-76269e901d0x" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

