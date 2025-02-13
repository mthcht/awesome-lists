rule MonitoringTool_MacOS_RealtimeSpy_B_349828_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/RealtimeSpy.B!MTB"
        threat_id = "349828"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "RealtimeSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Users/spytech/Desktop/source/Realtime-Spy/" ascii //weight: 1
        $x_1_2 = "Realtime-Spy/relaunch/main.m" ascii //weight: 1
        $x_1_3 = "Realtime-Spy.build/Debug/relaunch.build" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

