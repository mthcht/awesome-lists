rule MonitoringTool_AndroidOS_LoveTrap_B_354264_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/LoveTrap.B!MTB"
        threat_id = "354264"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "LoveTrap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UninstallActivity" ascii //weight: 1
        $x_1_2 = "pendingphones" ascii //weight: 1
        $x_1_3 = "NetworkTS" ascii //weight: 1
        $x_1_4 = "UPLOADLIMITED" ascii //weight: 1
        $x_1_5 = "Empty_Home" ascii //weight: 1
        $x_1_6 = "incoming_number" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

