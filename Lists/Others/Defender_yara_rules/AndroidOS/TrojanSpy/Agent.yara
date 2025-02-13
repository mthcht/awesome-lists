rule TrojanSpy_AndroidOS_Agent_A_2147744789_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Agent.A!MTB"
        threat_id = "2147744789"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/demo/prometheus/app/HomeBR;" ascii //weight: 1
        $x_1_2 = "$Lcom/demo/prometheus/bean/SmsEntity;" ascii //weight: 1
        $x_1_3 = "(android.intent.action.Upload.Call.Record" ascii //weight: 1
        $x_1_4 = "uploadInComingRecord time" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Agent_ES_2147798196_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Agent.ES!MTB"
        threat_id = "2147798196"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "app.lite.bot" ascii //weight: 1
        $x_1_2 = "ScreenRecorderService" ascii //weight: 1
        $x_1_3 = "/keylogger.txt" ascii //weight: 1
        $x_1_4 = "/uploaded_files.txt" ascii //weight: 1
        $x_1_5 = "/fetched_file_path.txt" ascii //weight: 1
        $x_1_6 = "/del_record" ascii //weight: 1
        $x_1_7 = "/proc/meminfo" ascii //weight: 1
        $x_1_8 = "Lapp/lite/bot/activities/LockMeNowActivity" ascii //weight: 1
        $x_1_9 = "SETTING_UPLOAD_USING_MOBILE_DATA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

