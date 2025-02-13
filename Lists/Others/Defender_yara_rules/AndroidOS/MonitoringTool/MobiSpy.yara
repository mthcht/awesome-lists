rule MonitoringTool_AndroidOS_MobiSpy_A_418743_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MobiSpy.A!MTB"
        threat_id = "418743"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MobiSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/psac/a/processservice" ascii //weight: 1
        $x_1_2 = "2audiouploadfiles" ascii //weight: 1
        $x_1_3 = "dumpWifi" ascii //weight: 1
        $x_1_4 = "saveCellDetails" ascii //weight: 1
        $x_1_5 = "upload_count_media" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

