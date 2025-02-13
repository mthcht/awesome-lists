rule MonitoringTool_AndroidOS_Mcare_A_332362_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Mcare.A!MTB"
        threat_id = "332362"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Mcare"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendSimChangeNotification" ascii //weight: 1
        $x_1_2 = "/rpc/notifyWipeout" ascii //weight: 1
        $x_1_3 = "requestLocationInfo" ascii //weight: 1
        $x_1_4 = "retrieveAppList" ascii //weight: 1
        $x_1_5 = "/backup/sendCallLog" ascii //weight: 1
        $x_1_6 = "sendScreenLockResult" ascii //weight: 1
        $x_1_7 = "mobiucare" ascii //weight: 1
        $x_5_8 = "com.mobiucare.client" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

