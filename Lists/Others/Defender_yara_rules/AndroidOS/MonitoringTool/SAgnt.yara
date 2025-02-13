rule MonitoringTool_AndroidOS_SAgnt_A_329613_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SAgnt.A!MTB"
        threat_id = "329613"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tracking_start_time" ascii //weight: 1
        $x_1_2 = "SMS_COORDINATES_FOUND" ascii //weight: 1
        $x_1_3 = "interpreteSMS" ascii //weight: 1
        $x_1_4 = "de/tracking/track/LocationTracker" ascii //weight: 1
        $x_1_5 = "phoneNumberToTrack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_SAgnt_B_343781_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SAgnt.B!MTB"
        threat_id = "343781"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "call_number=" ascii //weight: 1
        $x_1_2 = "startUpload " ascii //weight: 1
        $x_1_3 = "updateTrackerTable" ascii //weight: 1
        $x_1_4 = "track_location" ascii //weight: 1
        $x_1_5 = "getChromeBrowserHist" ascii //weight: 1
        $x_1_6 = "getSMSHistory" ascii //weight: 1
        $x_1_7 = "delOldDataToHistoryPhohe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule MonitoringTool_AndroidOS_SAgnt_D_344606_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SAgnt.D!MTB"
        threat_id = "344606"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tracked Cell Phones" ascii //weight: 1
        $x_1_2 = "App monitoring" ascii //weight: 1
        $x_1_3 = "monitored cell phones" ascii //weight: 1
        $x_1_4 = "Lcom/androidaplicativos/phonetrackerbynumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_SAgnt_E_350409_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SAgnt.E!MTB"
        threat_id = "350409"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ContactInfoActivity" ascii //weight: 1
        $x_1_2 = "UploadLogActivity" ascii //weight: 1
        $x_5_3 = "Lcom/hecom/mgm" ascii //weight: 5
        $x_1_4 = "DeviceMobileNetDBMInfo" ascii //weight: 1
        $x_1_5 = "hecom/pictmp/" ascii //weight: 1
        $x_1_6 = "kickedOutMsg" ascii //weight: 1
        $x_1_7 = "contactChatSearchHistory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_AndroidOS_SAgnt_C_355234_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SAgnt.C!MTB"
        threat_id = "355234"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SENT_SMS_TEXT" ascii //weight: 1
        $x_1_2 = "ru.perm.trubnikov.gps2sms" ascii //weight: 1
        $x_1_3 = "AnotherMsgActivity" ascii //weight: 1
        $x_1_4 = "send_receiver_fired" ascii //weight: 1
        $x_1_5 = "rupermtrubnikovgps2smsDB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule MonitoringTool_AndroidOS_SAgnt_F_359874_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SAgnt.F!MTB"
        threat_id = "359874"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tk.hasankassem.simchanged" ascii //weight: 1
        $x_1_2 = "MyDeviceAdminReceiver" ascii //weight: 1
        $x_1_3 = "mLastLocation" ascii //weight: 1
        $x_5_4 = "LostOfflinePro" ascii //weight: 5
        $x_5_5 = "tk.hasankassem" ascii //weight: 5
        $x_1_6 = "activity_forgot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_AndroidOS_SAgnt_G_366469_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SAgnt.G!MTB"
        threat_id = "366469"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.mosi.antitheftsecurity" ascii //weight: 1
        $x_1_2 = "LogcallService" ascii //weight: 1
        $x_1_3 = "SecretCallReceiver" ascii //weight: 1
        $x_1_4 = "wipedata" ascii //weight: 1
        $x_1_5 = "enable_detective" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

