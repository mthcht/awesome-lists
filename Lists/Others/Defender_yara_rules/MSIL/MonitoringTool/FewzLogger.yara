rule MonitoringTool_MSIL_FewzLogger_205391_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/FewzLogger"
        threat_id = "205391"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FewzLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FewzLogger" wide //weight: 1
        $x_1_2 = "-_=([!| Keyliee |!])=_-" wide //weight: 1
        $x_1_3 = "Ankama Shield Stealer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

