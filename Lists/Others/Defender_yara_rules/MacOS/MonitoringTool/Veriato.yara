rule MonitoringTool_MacOS_Veriato_A_367317_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Veriato.A!MTB"
        threat_id = "367317"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Veriato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "config/EmailInfo/Users/User" ascii //weight: 1
        $x_1_2 = "IChatInfo/lastProceedTime" ascii //weight: 1
        $x_1_3 = "/captureUrl" ascii //weight: 1
        $x_1_4 = "./blueprintsecid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

