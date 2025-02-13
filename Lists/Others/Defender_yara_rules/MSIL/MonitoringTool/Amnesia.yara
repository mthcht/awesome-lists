rule MonitoringTool_MSIL_Amnesia_204842_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/Amnesia"
        threat_id = "204842"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amnesia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Amnesia KeyLogger" wide //weight: 1
        $x_1_2 = "To Bring Up Again After Hiding : Ctrl+Alt+Z" wide //weight: 1
        $x_1_3 = "\\Log.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

