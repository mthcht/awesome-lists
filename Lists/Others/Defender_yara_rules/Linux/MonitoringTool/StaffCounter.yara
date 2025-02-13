rule MonitoringTool_Linux_StaffCounter_A_331553_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Linux/StaffCounter.A!MTB"
        threat_id = "331553"
        type = "MonitoringTool"
        platform = "Linux: Linux platform"
        family = "StaffCounter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "resume monitoring" ascii //weight: 1
        $x_1_2 = "screenshots/" ascii //weight: 1
        $x_1_3 = "/tmp/keys.log" ascii //weight: 1
        $x_1_4 = "settings/keystrokes" ascii //weight: 1
        $x_1_5 = "/logs/sent" ascii //weight: 1
        $x_1_6 = "/staffcounter.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

