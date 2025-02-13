rule MonitoringTool_MSIL_HawkEye_228581_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/HawkEye"
        threat_id = "228581"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HawkEye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HawkEye Keylogger" wide //weight: 1
        $x_1_2 = "HawkSpySoftwares" wide //weight: 1
        $x_1_3 = "KeyStroke Logs" wide //weight: 1
        $x_1_4 = "Clipboard Logs" wide //weight: 1
        $x_1_5 = "[YESStealer]" wide //weight: 1
        $x_1_6 = "[BlockWebsite]" wide //weight: 1
        $x_1_7 = "[YESKeyStroke]" wide //weight: 1
        $x_1_8 = "[FakeMsg]" wide //weight: 1
        $x_1_9 = "[YESScreeny]" wide //weight: 1
        $x_1_10 = "[YESClipboard]" wide //weight: 1
        $x_1_11 = "[NOSpreaders]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

