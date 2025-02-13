rule TrojanSpy_AndroidOS_Fakecall_A_2147780377_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecall.A!MTB"
        threat_id = "2147780377"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.spyss.mobilehardware.db.SmsItem" ascii //weight: 2
        $x_2_2 = "/spy/SyncDone?imei=" ascii //weight: 2
        $x_1_3 = "mobile_device_read_smss" ascii //weight: 1
        $x_1_4 = "autoSyncSmss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Fakecall_B_2147782154_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecall.B!MTB"
        threat_id = "2147782154"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lvip/system/core/net/entity/CallLogEntity" ascii //weight: 1
        $x_1_2 = "SmsUploadManager" ascii //weight: 1
        $x_1_3 = "a3_sanwamoney" ascii //weight: 1
        $x_1_4 = "INCOMING_CALL_STATE_OFFHOOK" ascii //weight: 1
        $x_1_5 = "a2_yujinbank.mp3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Fakecall_E_2147812783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecall.E!MTB"
        threat_id = "2147812783"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "spy/uploadMobileSmss" ascii //weight: 1
        $x_1_2 = "uploadMobileContacts" ascii //weight: 1
        $x_1_3 = "spy/downloadMobileContacts" ascii //weight: 1
        $x_1_4 = "syncMobileCallLogs" ascii //weight: 1
        $x_1_5 = "deleteMobileApp" ascii //weight: 1
        $x_1_6 = "com/amani/base" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Fakecall_D_2147813255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecall.D!MTB"
        threat_id = "2147813255"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/yaowan/code/receiver/CallLogObserver" ascii //weight: 1
        $x_1_2 = "CallRecordingDB" ascii //weight: 1
        $x_1_3 = "deleteCallRecording" ascii //weight: 1
        $x_1_4 = "UploadPhoneInfoRunnable" ascii //weight: 1
        $x_1_5 = "EXECUTE_COMMAND_RECORDING_TIMER_DELAY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Fakecall_C_2147813700_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecall.C!MTB"
        threat_id = "2147813700"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/securenet/assistant/PhoneCallActivity" ascii //weight: 1
        $x_1_2 = "injectIfNeededIn" ascii //weight: 1
        $x_1_3 = "TRANSACTION_onOutgoingCall" ascii //weight: 1
        $x_1_4 = "REQUEST_REDIRECT_CALL" ascii //weight: 1
        $x_1_5 = "smsInfoList" ascii //weight: 1
        $x_1_6 = "getMobileNO" ascii //weight: 1
        $x_1_7 = "lastRecordingDuration" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_Fakecall_F_2147815398_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecall.F!MTB"
        threat_id = "2147815398"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uploadCallLog" ascii //weight: 1
        $x_1_2 = "uploadRecordingFile" ascii //weight: 1
        $x_1_3 = "/user/upload_info_file" ascii //weight: 1
        $x_1_4 = "/user/upload_recording_file" ascii //weight: 1
        $x_1_5 = "/user/upload_images" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Fakecall_H_2147832192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecall.H!MTB"
        threat_id = "2147832192"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/spy/downloadMobileContacts" ascii //weight: 1
        $x_1_2 = "UploadMobileDataHelper" ascii //weight: 1
        $x_1_3 = "syncMobileCallLogs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Fakecall_K_2147832265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecall.K!MTB"
        threat_id = "2147832265"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6d 2f [0-64] 73 65 72 76 69 63 65 73 2f 43 61 6c 6c 4c 6f 67 53 65 72 76 69 63 65}  //weight: 1, accuracy: Low
        $x_1_2 = "restricted_numbers.db" ascii //weight: 1
        $x_1_3 = "uploadCallLog" ascii //weight: 1
        $x_1_4 = "/api/mobile/calllog" ascii //weight: 1
        $x_1_5 = "uploadCallLogFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Fakecall_J_2147832434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecall.J!MTB"
        threat_id = "2147832434"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendPhoneInfoToServer" ascii //weight: 1
        $x_1_2 = "runWhoWho" ascii //weight: 1
        $x_1_3 = "requestInstallUnknownApp" ascii //weight: 1
        $x_1_4 = "isInstalledWhoWho" ascii //weight: 1
        $x_1_5 = "starttracking" ascii //weight: 1
        $x_1_6 = "is_update" ascii //weight: 1
        $x_1_7 = "downloadWhoWho" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_Fakecall_I_2147834384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakecall.I!MTB"
        threat_id = "2147834384"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakecall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/wish/defaultcallservice/activity" ascii //weight: 1
        $x_1_2 = "get_limit_phone_number" ascii //weight: 1
        $x_1_3 = "/user/upload_images" ascii //weight: 1
        $x_1_4 = "/user/upload_recording_file" ascii //weight: 1
        $x_1_5 = "/user/upload_info_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

