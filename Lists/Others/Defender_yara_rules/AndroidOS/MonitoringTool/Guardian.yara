rule MonitoringTool_AndroidOS_Guardian_C_331939_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Guardian.C!MTB"
        threat_id = "331939"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Guardian"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.lenovo.safecenter" ascii //weight: 1
        $x_1_2 = "weibo.com/leanquan" ascii //weight: 1
        $x_1_3 = "qv_base.amf" ascii //weight: 1
        $x_1_4 = "UpLoadSMS" ascii //weight: 1
        $x_1_5 = "killprocess" ascii //weight: 1
        $x_1_6 = "LAST_SAVE_SENT_SMS_ID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

