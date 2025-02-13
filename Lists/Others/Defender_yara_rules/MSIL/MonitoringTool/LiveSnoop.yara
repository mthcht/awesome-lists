rule MonitoringTool_MSIL_LiveSnoop_205390_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/LiveSnoop"
        threat_id = "205390"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LiveSnoop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://livesnoop.com/client/postlog.php" wide //weight: 1
        $x_1_2 = "https://livesnoop.com/client/screenshots.php" wide //weight: 1
        $x_1_3 = "maxScreenshotsPerMinute:" wide //weight: 1
        $x_1_4 = "Webcam Upload Error:" wide //weight: 1
        $x_1_5 = "LiveSnoop_Agent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

