rule MonitoringTool_MSIL_CSKeylogger_205068_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/CSKeylogger"
        threat_id = "205068"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CSKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CS.KEYLOGGER" wide //weight: 1
        $x_1_2 = "Key logger Log file !" wide //weight: 1
        $x_1_3 = "Automatically email result log file" wide //weight: 1
        $x_1_4 = "Hotkey to return from stealth mode : Ctrl+Alt+Shift + (F12,F11,F10)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

