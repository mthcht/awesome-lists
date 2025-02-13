rule MonitoringTool_AndroidOS_Spyoo_172619_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spyoo"
        threat_id = "172619"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spyoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "logs/getsetting.aspx" ascii //weight: 1
        $x_1_2 = "log_gps.aspx" ascii //weight: 1
        $x_1_3 = "spyoo/Setting" ascii //weight: 1
        $x_1_4 = "SpyooService.java" ascii //weight: 1
        $x_1_5 = "capture_when_phone_move_over" ascii //weight: 1
        $x_1_6 = "http://www.copy9.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_AndroidOS_Spyoo_A_279689_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spyoo.A!MTB"
        threat_id = "279689"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spyoo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Root device and accept Super User for TheTruthSpy" ascii //weight: 2
        $x_2_2 = "Lcom/ispyoo/common/calltracker/" ascii //weight: 2
        $x_1_3 = "/data/com.whatsapp/databases/" ascii //weight: 1
        $x_1_4 = "/data/com.viber.voip/databases/" ascii //weight: 1
        $x_1_5 = "/data/com.facebook.katana/databases/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_AndroidOS_Spyoo_B_299509_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spyoo.B!MTB"
        threat_id = "299509"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spyoo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thetruthspy.com" ascii //weight: 1
        $x_1_2 = "Hide TheTruthSpy" ascii //weight: 1
        $x_1_3 = "ContactWatcher" ascii //weight: 1
        $x_1_4 = "SmsWatcher" ascii //weight: 1
        $x_1_5 = "CallWatcher" ascii //weight: 1
        $x_1_6 = "BrowsingHistoryWatcher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_AndroidOS_Spyoo_C_325147_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spyoo.C!MTB"
        threat_id = "325147"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spyoo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AndroidMonitorApplication" ascii //weight: 1
        $x_1_2 = "OutGoingCallReceiver" ascii //weight: 1
        $x_1_3 = "last_whatsapp_date" ascii //weight: 1
        $x_1_4 = "com/ispyoo/common/monitor/SpyApp" ascii //weight: 1
        $x_1_5 = "is_record_call_active" ascii //weight: 1
        $x_1_6 = "/log_call_recording.aspx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Spyoo_A_328569_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Spyoo.A!xp"
        threat_id = "328569"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Spyoo"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/logs/setsetting.aspx" ascii //weight: 1
        $x_1_2 = "senddeviceinfo.aspx" ascii //weight: 1
        $x_1_3 = "spycallnumber" ascii //weight: 1
        $x_1_4 = "flagspycall" ascii //weight: 1
        $x_1_5 = "onCaptureSharedElementSnapshot" ascii //weight: 1
        $x_1_6 = "www.spytic.fr" ascii //weight: 1
        $x_1_7 = "iits.service.SpyooService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

