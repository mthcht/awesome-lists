rule TrojanSpy_Win32_MiniKeyLog_E_2147574437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/MiniKeyLog.E"
        threat_id = "2147574437"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "MiniKeyLog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Mini Key Log - PC Monitoring Software" ascii //weight: 3
        $x_2_2 = "  <description>PC Monitoring Software</description>" ascii //weight: 2
        $x_1_3 = "hecks" ascii //weight: 1
        $x_1_4 = "DI'm sorry, this application will not run while Soft-Ice is running." ascii //weight: 1
        $x_2_5 = " 2002-2007 by blue-series" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

