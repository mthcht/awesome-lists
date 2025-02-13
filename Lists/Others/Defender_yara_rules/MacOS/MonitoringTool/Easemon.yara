rule MonitoringTool_MacOS_Easemon_A_334369_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MacOS/Easemon.A!MTB"
        threat_id = "334369"
        type = "MonitoringTool"
        platform = "MacOS: "
        family = "Easemon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "easemon" ascii //weight: 1
        $x_1_2 = "com.ab.em.update.plist" ascii //weight: 1
        $x_1_3 = "ccc707d2924768f2cc12bc8b" ascii //weight: 1
        $x_1_4 = "chflags -R hidden" ascii //weight: 1
        $x_1_5 = "dscl . -ls /Users home | grep -i /User" ascii //weight: 1
        $x_1_6 = "uploadWebHistory" ascii //weight: 1
        $x_1_7 = "ikm.awsapi.io/index.php?m=api&a=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

