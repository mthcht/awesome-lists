rule MonitoringTool_MSIL_PCDataManager_205044_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/PCDataManager"
        threat_id = "205044"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PCDataManager"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PC Data manager has facilities to hide these shortcuts and to access the software using hidden methods" wide //weight: 1
        $x_1_2 = "Specify the email address here that you want PC Data Manager to use for sending the activity logs as attachment" wide //weight: 1
        $x_1_3 = "Please find the Keystrokes Log recorded and created by PC Data Manager" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

