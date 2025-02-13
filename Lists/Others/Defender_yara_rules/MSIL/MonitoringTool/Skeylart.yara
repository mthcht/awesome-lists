rule MonitoringTool_MSIL_Skeylart_169294_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/Skeylart"
        threat_id = "169294"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Skeylart"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Steel Keylogger" wide //weight: 1
        $x_1_2 = "Thankyou Leon for testing!" wide //weight: 1
        $x_1_3 = "The title of the fake connection showed. Make it as realistic" wide //weight: 1
        $x_1_4 = "Starts up the keylogger when the computer loads" wide //weight: 1
        $x_1_5 = "administrators only. Close Steel.exe" wide //weight: 1
        $x_1_6 = "thepiratebay.org/user/_Smithy_" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

