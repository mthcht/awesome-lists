rule MonitoringTool_Win32_BossEveryware_14880_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/BossEveryware"
        threat_id = "14880"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BossEveryware"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Jmerik\\BossEveryware\\" ascii //weight: 1
        $x_1_2 = "wsa32" ascii //weight: 1
        $x_1_3 = "[Logging finished]" ascii //weight: 1
        $x_2_4 = "bewldr32.exe /s" ascii //weight: 2
        $x_2_5 = "[Logging started]" ascii //weight: 2
        $x_1_6 = "PARENT_WIN" ascii //weight: 1
        $x_1_7 = "PRSCR" ascii //weight: 1
        $x_1_8 = "No logger available" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

