rule MonitoringTool_MSIL_CyborgLog_212471_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/CyborgLog"
        threat_id = "212471"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CyborgLog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cyborg v2.0 :-:-:" wide //weight: 1
        $x_1_2 = "ataDdneS" wide //weight: 1
        $x_1_3 = "KeyboardHook" ascii //weight: 1
        $x_1_4 = "[Window:]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

