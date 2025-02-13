rule MonitoringTool_Win32_SystemSurveillance_121306_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SystemSurveillance"
        threat_id = "121306"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemSurveillance"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {50 7f 53 79 73 74 65 6d 20 53 75 72 76 65 69 6c 6c 61 6e 63 65 20 50 72 6f 00 09 4a 00 66 31 39 00 00 00 31 33 32 7f 25 53 59 53 25 7f 00 09 09 00 66 31 36 00 00 00 30 7f 53 59 53 7f 25 57 49 4e 25 00}  //weight: 5, accuracy: High
        $x_1_2 = "downloads\\sspro\\internet\\gp" ascii //weight: 1
        $x_1_3 = "System Surveillance " ascii //weight: 1
        $x_1_4 = "AddItem(%WIN%\\ssp32hp.chm,Help Manual,%WIN%\\ssp32hp" ascii //weight: 1
        $x_1_5 = "DeleteGroup(System Surveillance " ascii //weight: 1
        $x_1_6 = "%DESKTOPDIR%\\SystemSurveillancePro.htm" ascii //weight: 1
        $x_1_7 = "emailsnapshotinterval=%INI_SS_EMAILSNAPSHOTINTERVAL%" ascii //weight: 1
        $x_1_8 = "clearlogsafteremail=%INI_LOGS_CLEARLOGSAFTEREMAIL%" ascii //weight: 1
        $x_1_9 = "then restart the System Surveillance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

