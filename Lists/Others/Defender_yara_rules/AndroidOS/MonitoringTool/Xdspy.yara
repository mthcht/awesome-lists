rule MonitoringTool_AndroidOS_Xdspy_A_355727_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Xdspy.A!MTB"
        threat_id = "355727"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Xdspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MessageScrapper" ascii //weight: 1
        $x_1_2 = "TOKEN_HACKER" ascii //weight: 1
        $x_1_3 = "getsms" ascii //weight: 1
        $x_1_4 = "getContacts" ascii //weight: 1
        $x_1_5 = "getCallsLogs" ascii //weight: 1
        $x_1_6 = "getInstalledApps" ascii //weight: 1
        $x_1_7 = "xd.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

