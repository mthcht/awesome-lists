rule MonitoringTool_MSIL_Limitless_199546_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/Limitless"
        threat_id = "199546"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Limitless"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WEBSITELINK" wide //weight: 1
        $x_1_2 = "Failed To Start Sending Thread." wide //weight: 1
        $x_1_3 = "--::]" wide //weight: 1
        $x_1_4 = "SetFpassword" wide //weight: 1
        $x_1_5 = "FTPUpload" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_MSIL_Limitless_199546_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/Limitless"
        threat_id = "199546"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Limitless"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "No Logs Were Recorded. Not Sending A Log..." wide //weight: 1
        $x_1_2 = "--::]" wide //weight: 1
        $x_1_3 = "Limitless Logger : :" wide //weight: 1
        $x_1_4 = "FTPUpload" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_MSIL_Limitless_199546_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/Limitless"
        threat_id = "199546"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Limitless"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed To Start Sending Thread." wide //weight: 1
        $x_1_2 = "Limitless Logger : : Keyboard" wide //weight: 1
        $x_1_3 = "Keyboard Records : :" wide //weight: 1
        $x_1_4 = {73 63 72 65 65 6e 73 68 6f 74 43 6f 75 6e 74 00 63 61 70 74 75 72 65 53 63 72 65 65 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = "createLowLevelKeyboardHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

