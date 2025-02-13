rule MonitoringTool_AndroidOS_Pholoc_A_305595_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Pholoc.A!MTB"
        threat_id = "305595"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Pholoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "web.me.com" ascii //weight: 1
        $x_1_2 = "rvoandev/PhoneLocator/Pro_version.html" ascii //weight: 1
        $x_1_3 = "shortLog outgoing" ascii //weight: 1
        $x_1_4 = "Lock device on screen" ascii //weight: 1
        $x_1_5 = "send email fm Location" ascii //weight: 1
        $x_1_6 = "text_SimCheck_locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

