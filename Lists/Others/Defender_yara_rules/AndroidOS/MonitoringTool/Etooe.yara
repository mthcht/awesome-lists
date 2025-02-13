rule MonitoringTool_AndroidOS_Etooe_A_350371_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Etooe.A!MTB"
        threat_id = "350371"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Etooe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.wangling.remotephone" ascii //weight: 1
        $x_1_2 = "LocationMap.php" ascii //weight: 1
        $x_1_3 = "ykz.e2eye.com/cloudctrl" ascii //weight: 1
        $x_1_4 = "SmsComeReceiver" ascii //weight: 1
        $x_1_5 = "MobileCameraService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

