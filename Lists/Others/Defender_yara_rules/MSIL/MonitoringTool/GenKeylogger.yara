rule MonitoringTool_MSIL_GenKeylogger_205303_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/GenKeylogger"
        threat_id = "205303"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GenKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Send an email notification when Keylogger starts" wide //weight: 1
        $x_1_2 = "Immediately hide Keylogger when logging starts" wide //weight: 1
        $x_1_3 = "If you want to show the Keylogger program again later, press CTRL + ALT + Z" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

