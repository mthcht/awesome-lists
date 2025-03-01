rule MonitoringTool_MacOS_EaseMon_K_419855_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/EaseMon.K!MTB"
        threat_id = "419855"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "EaseMon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.ikm.macos.useragent.plist" ascii //weight: 1
        $x_1_2 = "Unload keystrokes kext" ascii //weight: 1
        $x_1_3 = "com.em.messageport.Update" ascii //weight: 1
        $x_1_4 = "/Library/Application Support/ikeymonitor-support/" ascii //weight: 1
        $x_1_5 = "screencapture -xC -tjpg %@" ascii //weight: 1
        $x_1_6 = "uploadScreenshots" ascii //weight: 1
        $x_1_7 = "ikm.awsapi.io/index.php?m=api&a=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

