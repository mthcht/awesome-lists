rule MonitoringTool_MSIL_PCDataManagerBasic_205042_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/PCDataManagerBasic"
        threat_id = "205042"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PCDataManagerBasic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PC Data Manager Software (Basic Edition)" wide //weight: 1
        $x_1_2 = "Are you sure to hide PC Data Manager with stopped recording status" wide //weight: 1
        $x_1_3 = "Please find the Keystrokes Log recorded and created by PC Data Manager" wide //weight: 1
        $x_1_4 = "Are you sure you want to uninstall PC Data Manager" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_MSIL_PCDataManagerBasic_205042_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/PCDataManagerBasic"
        threat_id = "205042"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PCDataManagerBasic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PC Management - Basic has facilities to hide these shortcuts and to access the software using hidden methods" wide //weight: 1
        $x_1_2 = "Specify the email address here that you want PC Management - Basic to use for sending the activity logs as attachment" wide //weight: 1
        $x_1_3 = "Please find the Keystrokes Activities Log recorded and created by DRPU PC Management" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

