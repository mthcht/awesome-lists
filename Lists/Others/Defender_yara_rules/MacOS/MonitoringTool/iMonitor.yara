rule MonitoringTool_MacOS_iMonitor_K_368395_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/iMonitor.K!MTB"
        threat_id = "368395"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "iMonitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Users/imonitor/Desktop/EAM/imonitor/imonitor/" ascii //weight: 1
        $x_1_2 = "/library/imonitor/keystrokes.cfg" ascii //weight: 1
        $x_1_3 = "%@/keywndlog.cfg" ascii //weight: 1
        $x_1_4 = "%@/filelog.cfg" ascii //weight: 1
        $x_1_5 = "%@/clipboard.cfg" ascii //weight: 1
        $x_1_6 = "isimonitorrunning" ascii //weight: 1
        $x_1_7 = "updateeamserverip" ascii //weight: 1
        $x_1_8 = "/library/imonitor/lastping.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

