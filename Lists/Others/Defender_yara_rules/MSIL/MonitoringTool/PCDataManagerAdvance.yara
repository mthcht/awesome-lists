rule MonitoringTool_MSIL_PCDataManagerAdvance_205043_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/PCDataManagerAdvance"
        threat_id = "205043"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PCDataManagerAdvance"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PC Management - Advanced has facilities to hide these shortcuts and to access the software using hidden methods" wide //weight: 1
        $x_1_2 = "Specify the email address here that you want PC Management - Advanced to use for sending the activity logs as attachment" wide //weight: 1
        $x_1_3 = "DRPU PC Management - Advanced Report" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

