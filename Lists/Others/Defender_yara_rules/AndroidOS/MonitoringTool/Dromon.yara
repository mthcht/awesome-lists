rule MonitoringTool_AndroidOS_Dromon_A_329263_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Dromon.A!MTB"
        threat_id = "329263"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Dromon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 04 11 04 d8 04 [0-2] ff 23 [0-3] 05 12 [0-2] 12 [0-2] 34 [0-2] 07 00 71 10 [0-3] 00 0c 04 28 f3 39 [0-2] 07 00 44 [0-2] 07 [0-2] d8 [0-3] 01 28 f3 d8 04 [0-2] ff 44 05 07 [0-2] d0 55 80 00 d4 [0-2] 80 00 b1 65 d4 55 80 00 8e 55 50 05 [0-1] 04 28 ef}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Dromon_A_329263_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Dromon.A!MTB"
        threat_id = "329263"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Dromon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendLogsReceiver" ascii //weight: 1
        $x_1_2 = "CheckCallNumber" ascii //weight: 1
        $x_1_3 = "DelComandSms" ascii //weight: 1
        $x_1_4 = "SendLogFiles" ascii //weight: 1
        $x_1_5 = "getinfo/Tools;" ascii //weight: 1
        $x_1_6 = "Lcom/amon/SmsReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Dromon_B_345107_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Dromon.B!MTB"
        threat_id = "345107"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Dromon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "info_prog_sms_comand" ascii //weight: 1
        $x_1_2 = "ScreenCapturePermissionActivity" ascii //weight: 1
        $x_1_3 = "info_prog_call_record_success" ascii //weight: 1
        $x_1_4 = "info_setings_KeyLoggerApps" ascii //weight: 1
        $x_1_5 = "info_setings_enableCalls" ascii //weight: 1
        $x_1_6 = "info_queue_send_data_to_server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

