rule MonitoringTool_AndroidOS_Aspy_D_346057_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Aspy.D!MTB"
        threat_id = "346057"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Aspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sms.AddRecord" ascii //weight: 1
        $x_1_2 = "RecordGps" ascii //weight: 1
        $x_1_3 = "RecordClipboard" ascii //weight: 1
        $x_5_4 = "a-spy" ascii //weight: 5
        $x_1_5 = "AccScreenshot.takeScreenshot" ascii //weight: 1
        $x_1_6 = "RecordScreenRoot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_AndroidOS_Aspy_E_357608_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Aspy.E!MTB"
        threat_id = "357608"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Aspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Lcom/as/facecapture" ascii //weight: 5
        $x_5_2 = "a-spy" ascii //weight: 5
        $x_1_3 = "deletedall" ascii //weight: 1
        $x_1_4 = "hide_notification" ascii //weight: 1
        $x_1_5 = "start_capture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_AndroidOS_Aspy_F_359620_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Aspy.F!MTB"
        threat_id = "359620"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Aspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.as.keylogger" ascii //weight: 1
        $x_1_2 = "keylogger_Broadcast" ascii //weight: 1
        $x_1_3 = "activate_acc_message" ascii //weight: 1
        $x_1_4 = "ask_delete_all" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Aspy_G_360474_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Aspy.G!MTB"
        threat_id = "360474"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Aspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.as.urllogger" ascii //weight: 1
        $x_1_2 = "urllogger_Broadcast" ascii //weight: 1
        $x_1_3 = "ask_delete_all" ascii //weight: 1
        $x_1_4 = "apk.urllogger.App" ascii //weight: 1
        $x_1_5 = "activate_acc_message" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule MonitoringTool_AndroidOS_Aspy_H_361803_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Aspy.H!MTB"
        threat_id = "361803"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Aspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kgl_Broadcast" ascii //weight: 1
        $x_1_2 = "ask_delete_all" ascii //weight: 1
        $x_1_3 = "activate_acc_message" ascii //weight: 1
        $x_1_4 = "apk.kgl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Aspy_C_406899_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Aspy.C!MTB"
        threat_id = "406899"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Aspy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a-spy.com/?app=com.as.keylogger" ascii //weight: 1
        $x_1_2 = "com.as.keylogger" ascii //weight: 1
        $x_1_3 = "keylogger_Broadcast" ascii //weight: 1
        $x_1_4 = "AccSvc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

