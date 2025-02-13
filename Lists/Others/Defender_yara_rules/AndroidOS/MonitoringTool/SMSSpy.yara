rule MonitoringTool_AndroidOS_SMSSpy_A_309275_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SMSSpy.A!MTB"
        threat_id = "309275"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "showSpyDialog" ascii //weight: 1
        $x_1_2 = "smsspyLock:" ascii //weight: 1
        $x_1_3 = "spyview_email" ascii //weight: 1
        $x_1_4 = "sms return in SMSUtil" ascii //weight: 1
        $x_1_5 = "spy service starts" ascii //weight: 1
        $x_1_6 = "This is SMS Spy. It just looks like a Tip Calculator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

