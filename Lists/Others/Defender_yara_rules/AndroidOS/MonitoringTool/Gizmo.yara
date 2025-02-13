rule MonitoringTool_AndroidOS_Gizmo_B_325504_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Gizmo.B!MTB"
        threat_id = "325504"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Gizmo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_phone_config.php" ascii //weight: 1
        $x_1_2 = "SMSRecord" ascii //weight: 1
        $x_1_3 = "lastPhoneLogDate" ascii //weight: 1
        $x_1_4 = "mms_insert.php" ascii //weight: 1
        $x_1_5 = "lastBrowserDate" ascii //weight: 1
        $x_1_6 = "trackemail" ascii //weight: 1
        $x_1_7 = "recordcalls" ascii //weight: 1
        $x_1_8 = "backupDataBaseLiveToSDCard" ascii //weight: 1
        $x_1_9 = "files/phoneHistory.txt" ascii //weight: 1
        $x_1_10 = "files/deviceinfo.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule MonitoringTool_AndroidOS_Gizmo_C_431366_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Gizmo.C!MTB"
        threat_id = "431366"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Gizmo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.gizmoquip.smstracker" ascii //weight: 1
        $x_1_2 = "CallLogObserver" ascii //weight: 1
        $x_1_3 = "SmsObserver" ascii //weight: 1
        $x_1_4 = "registrations.smstracker.com" ascii //weight: 1
        $x_1_5 = "SMSTrackerAPIService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

