rule MonitoringTool_AndroidOS_Cobblerone_A_299707_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Cobblerone.A!MTB"
        threat_id = "299707"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Cobblerone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Please call xxxxxxxx to find the phone owner." ascii //weight: 1
        $x_1_2 = "WipePhone" ascii //weight: 1
        $x_1_3 = "WIPE_SDCARD_SMS" ascii //weight: 1
        $x_1_4 = "force_lock" ascii //weight: 1
        $x_1_5 = "/phonelock_test_folder/" ascii //weight: 1
        $x_1_6 = "sms_to_hide_sdcard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

