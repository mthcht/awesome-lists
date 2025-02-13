rule Spammer_Win32_Agent_AM_2147594943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Agent.AM"
        threat_id = "2147594943"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Data\\Address46" ascii //weight: 2
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Data\\Auth46" ascii //weight: 2
        $x_1_3 = "Microsoft\\Internet Explorer\\prndrv.dll" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Filter" ascii //weight: 1
        $x_1_5 = "Script execution failed" ascii //weight: 1
        $x_1_6 = "__PROXY_MUTEX_%d__" ascii //weight: 1
        $x_1_7 = ".SubmitFormImage" ascii //weight: 1
        $x_1_8 = ".ClickHyperlink" ascii //weight: 1
        $x_1_9 = "72.232.136.59" ascii //weight: 1
        $x_1_10 = ".SubmitForm" ascii //weight: 1
        $x_1_11 = "proxy2.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

