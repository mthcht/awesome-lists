rule MonitoringTool_MSIL_PCDataManagerFull_205046_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/PCDataManagerFull"
        threat_id = "205046"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PCDataManagerFull"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PC Data Manager Report" wide //weight: 1
        $x_1_2 = "At least one System or Internet activity must be selected to send log in log settings" wide //weight: 1
        $x_1_3 = "Please find the System Activities Log recorded and created by PC Data Manager" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

