rule MonitoringTool_AndroidOS_SpyMie_A_321865_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyMie.A!MTB"
        threat_id = "321865"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyMie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com/spylogger/app/spylogger" ascii //weight: 2
        $x_1_2 = "/utils/KeyLogger" ascii //weight: 1
        $x_1_3 = "/utils/SendMail" ascii //weight: 1
        $x_1_4 = "storeRecord" ascii //weight: 1
        $x_1_5 = "|(TEXT)|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

