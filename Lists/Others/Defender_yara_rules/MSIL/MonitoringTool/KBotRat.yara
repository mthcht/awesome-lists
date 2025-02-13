rule MonitoringTool_MSIL_KBotRat_233581_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/KBotRat"
        threat_id = "233581"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KBotRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/command.php" wide //weight: 1
        $x_1_2 = "{\"vicname\":\"(.*" wide //weight: 1
        $x_1_3 = "/supload.php" wide //weight: 1
        $x_1_4 = "\\Stub.exe" wide //weight: 1
        $x_1_5 = "Done ! Create Server in :" wide //weight: 1
        $x_1_6 = "kBotClient" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

