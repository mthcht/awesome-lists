rule MonitoringTool_Win32_PCAcme_14879_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PCAcme"
        threat_id = "14879"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PCAcme"
        severity = "10"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "<notlogged>" ascii //weight: 2
        $x_2_2 = "InternetGetConnectedState" ascii //weight: 2
        $x_1_3 = "is PC Acme report" ascii //weight: 1
        $x_1_4 = {50 43 20 41 63 6d 65 00 4b 45 52 4e 45 4c 33 32}  //weight: 1, accuracy: High
        $x_1_5 = "copy of PC Acme" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

