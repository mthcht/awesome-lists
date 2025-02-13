rule MonitoringTool_MSIL_BestFreeKeylogger_205026_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/BestFreeKeylogger"
        threat_id = "205026"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BestFreeKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Unhide Best Free Keylogger" wide //weight: 10
        $x_10_2 = "Uninstall other keyloggers before use best free keylogger if you have installed" wide //weight: 10
        $x_10_3 = "RegisterFKL.resources" ascii //weight: 10
        $x_1_4 = "chkEnableClipLog" ascii //weight: 1
        $x_1_5 = "chkEnableScreenshots" ascii //weight: 1
        $x_1_6 = "chkEnableKeyLog" ascii //weight: 1
        $x_1_7 = "chkDonotUsbScreen" ascii //weight: 1
        $x_1_8 = "chkDonotEmailScreen" ascii //weight: 1
        $x_1_9 = "chkDonotFtpScreen" ascii //weight: 1
        $x_1_10 = "chkDonotNetworkScreen" ascii //weight: 1
        $x_1_11 = "chkEnableEmailLoging" ascii //weight: 1
        $x_1_12 = "chkEnableUsbLoging" ascii //weight: 1
        $x_1_13 = "chkEnableFTPLoging" ascii //weight: 1
        $x_1_14 = "chkEnableLanLoging" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

