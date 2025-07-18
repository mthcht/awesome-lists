rule TrojanSpy_AndroidOS_SAgnt_B_2147787765_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.B!MTB"
        threat_id = "2147787765"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 73 6d 73 ?? ?? ?? ?? 2e 70 68 70 3f 75 70 6c 6f 61 64 73 6d 73 3d}  //weight: 2, accuracy: Low
        $x_1_2 = "UploadFilePhp" ascii //weight: 1
        $x_1_3 = "/Sms.txt" ascii //weight: 1
        $x_1_4 = "UploadKill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_D_2147810953_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.D!MTB"
        threat_id = "2147810953"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 0a 00 83 66 cd 64 8a 44 b7 04 71 20 ?? 00 42 00 0c 02 71 10 ?? ?? 02 00 0c 02 d8 00 00 01 28 ?? 71 20}  //weight: 1, accuracy: Low
        $x_1_2 = "EirvAppComponentFactoryStub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_D_2147810953_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.D!MTB"
        threat_id = "2147810953"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "contacts.json" ascii //weight: 1
        $x_1_2 = "sms.json" ascii //weight: 1
        $x_1_3 = "getCallsLogs" ascii //weight: 1
        $x_1_4 = "getSMS" ascii //weight: 1
        $x_1_5 = "getContacts" ascii //weight: 1
        $x_1_6 = "Lcom/cr/chat/activities" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_C_2147815317_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.C!MTB"
        threat_id = "2147815317"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsObserver" ascii //weight: 1
        $x_1_2 = "uploadContacts" ascii //weight: 1
        $x_1_3 = "/api/uploads/apisms" ascii //weight: 1
        $x_1_4 = "NEED_ALBUM" ascii //weight: 1
        $x_1_5 = "/api/uploads/callhis" ascii //weight: 1
        $x_1_6 = "NEED_CALL_LOG" ascii //weight: 1
        $x_1_7 = "/api/uploads/apimap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_G_2147815319_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.G!MTB"
        threat_id = "2147815319"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendFileDetailed" ascii //weight: 1
        $x_1_2 = "sentTosver" ascii //weight: 1
        $x_1_3 = "sendContactsDetails" ascii //weight: 1
        $x_1_4 = "//call_log/calls" ascii //weight: 1
        $x_1_5 = "sendGET" ascii //weight: 1
        $x_1_6 = "sendMyStuffDetailed" ascii //weight: 1
        $x_1_7 = "storeGPS" ascii //weight: 1
        $x_1_8 = "sentMicRecording" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_H_2147815372_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.H!MTB"
        threat_id = "2147815372"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/.temp/.data/SMS_RT" ascii //weight: 1
        $x_1_2 = "sendPhoneInfo" ascii //weight: 1
        $x_1_3 = "rec_info" ascii //weight: 1
        $x_1_4 = "APPSTATESENTNUM" ascii //weight: 1
        $x_1_5 = "debug_SMS" ascii //weight: 1
        $x_1_6 = "sendCurrentInfo" ascii //weight: 1
        $x_1_7 = "/.temp/Job_Log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_E_2147815373_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.E!MTB"
        threat_id = "2147815373"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SpyScreenshots" ascii //weight: 1
        $x_1_2 = "spyDatabase" ascii //weight: 1
        $x_1_3 = "ttps://r4dc3btbyzip0edkbykb1qteulwb.de/" ascii //weight: 1
        $x_1_4 = "getActiveSubscriptionInfoList" ascii //weight: 1
        $x_1_5 = "findaccessibilitynodeinfosbyviewid" ascii //weight: 1
        $x_1_6 = "sendDataToSocket" ascii //weight: 1
        $x_1_7 = "is_read_sms" ascii //weight: 1
        $x_1_8 = "savecalllogstodatabase" ascii //weight: 1
        $x_1_9 = "contactsData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_I_2147815374_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.I!MTB"
        threat_id = "2147815374"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendSMSAll" ascii //weight: 1
        $x_1_2 = "datatransfer/datasnapshot" ascii //weight: 1
        $x_1_3 = "sendContacts" ascii //weight: 1
        $x_1_4 = "submitDataByDoPost" ascii //weight: 1
        $x_1_5 = "sendSent" ascii //weight: 1
        $x_1_6 = "deletesms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_F_2147815399_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.F!MTB"
        threat_id = "2147815399"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dalbam.vip" ascii //weight: 1
        $x_1_2 = "v3/collect/getToken" ascii //weight: 1
        $x_1_3 = "sendCalllogs" ascii //weight: 1
        $x_1_4 = "sendDeviceInfos" ascii //weight: 1
        $x_1_5 = "sendAddressbooks" ascii //weight: 1
        $x_1_6 = "getWebSocketClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_K_2147818678_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.K!MTB"
        threat_id = "2147818678"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "setSendtoServer" ascii //weight: 1
        $x_1_2 = "deliverSelfNotifications" ascii //weight: 1
        $x_1_3 = "ContactsObserver" ascii //weight: 1
        $x_1_4 = "newSmsAdded" ascii //weight: 1
        $x_1_5 = "AudioRecordingService" ascii //weight: 1
        $x_1_6 = "CallSyncService" ascii //weight: 1
        $x_1_7 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f [0-24] 6d 6f 6e 69 74 6f 72 69 6e 67 2f 73 79 73 74 65 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_L_2147820255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.L!MTB"
        threat_id = "2147820255"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/moez/QKSMS/injection" ascii //weight: 1
        $x_1_2 = {61 70 70 6d 65 73 73 61 67 67 69 32 30 32 32 2e [0-3] 2f 61 70 70}  //weight: 1, accuracy: Low
        $x_1_3 = "hideFromLauncher" ascii //weight: 1
        $x_1_4 = "getConversationRepo" ascii //weight: 1
        $x_1_5 = "SmsReceiver_MembersInjector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_J_2147823564_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.J!MTB"
        threat_id = "2147823564"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Lcom/myapp/ratjs/Tools" ascii //weight: 10
        $x_1_2 = "sendLocation/" ascii //weight: 1
        $x_1_3 = "sendcalllog" ascii //weight: 1
        $x_1_4 = "sendallsms" ascii //weight: 1
        $x_1_5 = "sendApps" ascii //weight: 1
        $x_1_6 = "sendDeviceName" ascii //weight: 1
        $x_1_7 = "sendContact" ascii //weight: 1
        $x_1_8 = "SMS_SENT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SAgnt_M_2147823635_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.M!MTB"
        threat_id = "2147823635"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getDeviceSerialMD5" ascii //weight: 1
        $x_1_2 = "myBtnMsg" ascii //weight: 1
        $x_1_3 = "isMobileNO" ascii //weight: 1
        $x_1_4 = "deleteSMS" ascii //weight: 1
        $x_1_5 = "com.qihu360.mylive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_O_2147825010_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.O!MTB"
        threat_id = "2147825010"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/postman/search/online/activity" ascii //weight: 1
        $x_1_2 = "removeScreenLockCode" ascii //weight: 1
        $x_1_3 = "hideIcon" ascii //weight: 1
        $x_1_4 = "isScrlocked" ascii //weight: 1
        $x_1_5 = "lockScreenWithCode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_P_2147826883_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.P!MTB"
        threat_id = "2147826883"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "openSMS" ascii //weight: 1
        $x_1_2 = "ServiceNotifOverlay" ascii //weight: 1
        $x_1_3 = "openListener" ascii //weight: 1
        $x_1_4 = "/moc.onapees" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_N_2147828186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.N!MTB"
        threat_id = "2147828186"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 06 03 01 6e 10 21 00 06 00 0c 00 1a 07 03 00 6e 20 38 00 70 00 0a 00 38 00 30 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 10 05 00 06 00 0c 01 54 60 03 00 71 10 2e 00 00 00 0c 00 6e 10 33 00 00 00 0c 00 1f 00 03 00 5b 60 04 00 1c 00 03 00 1a 02 4d 00 12 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_Q_2147829556_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.Q!MTB"
        threat_id = "2147829556"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetAllContacts" ascii //weight: 1
        $x_1_2 = "_smsmessages1" ascii //weight: 1
        $x_1_3 = "CallLogWrapper" ascii //weight: 1
        $x_1_4 = "-deviceinfo.txt" ascii //weight: 1
        $x_1_5 = "SmsWrapper" ascii //weight: 1
        $x_1_6 = "screenrecord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_R_2147830988_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.R!MTB"
        threat_id = "2147830988"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uploadDeviceInfo" ascii //weight: 1
        $x_1_2 = "messageToAllContacts" ascii //weight: 1
        $x_1_3 = "captureMicrophone" ascii //weight: 1
        $x_1_4 = "captureCameraMain" ascii //weight: 1
        $x_1_5 = "uploadContact" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_S_2147832912_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.S!MTB"
        threat_id = "2147832912"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "forward_phone" ascii //weight: 1
        $x_1_2 = "activity_sms" ascii //weight: 1
        $x_1_3 = "SMSGetBroadcastReceiver" ascii //weight: 1
        $x_1_4 = "reloadForward data" ascii //weight: 1
        $x_10_5 = "Lcom/company/credit" ascii //weight: 10
        $x_1_6 = "NotificationCollectorService" ascii //weight: 1
        $x_1_7 = "upLoadMsg" ascii //weight: 1
        $x_1_8 = "uploadCallRecord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SAgnt_U_2147834056_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.U!MTB"
        threat_id = "2147834056"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "onDoneCapturingAllPhotos" ascii //weight: 1
        $x_5_2 = "squaredevapps.com/scoringservice/newService.php" ascii //weight: 5
        $x_1_3 = "getSMSData" ascii //weight: 1
        $x_1_4 = "getCallLogs" ascii //weight: 1
        $x_1_5 = "GPSTracker" ascii //weight: 1
        $x_5_6 = "square.nadra.tax.taxinfo" ascii //weight: 5
        $x_1_7 = "SendData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SAgnt_W_2147834160_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.W!MTB"
        threat_id = "2147834160"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/my114/" ascii //weight: 1
        $x_1_2 = "php.114my.com.cn/index.php?" ascii //weight: 1
        $x_1_3 = "m.kangbomech.com?timestamp=" ascii //weight: 1
        $x_1_4 = "SuperPhoneActivity" ascii //weight: 1
        $x_1_5 = "m=Home&c=Employee&a=set_location" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_T_2147835539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.T!MTB"
        threat_id = "2147835539"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/apps/microsoftwordapk" ascii //weight: 1
        $x_1_2 = "wordresume.herokuapp.com" ascii //weight: 1
        $x_1_3 = "pakcert.syncservice.org" ascii //weight: 1
        $x_1_4 = "file_upload" ascii //weight: 1
        $x_1_5 = "encryptData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_X_2147835540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.X!MTB"
        threat_id = "2147835540"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/demo/prometheus/api/ApiManager" ascii //weight: 1
        $x_1_2 = "contacts.db" ascii //weight: 1
        $x_1_3 = "killProcess" ascii //weight: 1
        $x_1_4 = "uploadCallRecord" ascii //weight: 1
        $x_1_5 = "android.intent.action.Upload.Call.Record" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_AZ_2147837272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.AZ!MTB"
        threat_id = "2147837272"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rewardapp.in/api/message.php" ascii //weight: 1
        $x_1_2 = "com/tk_1/icicibanknew" ascii //weight: 1
        $x_1_3 = "rewardapp.in/api/cards.php" ascii //weight: 1
        $x_1_4 = "ScreenOnOffBackgroundService" ascii //weight: 1
        $x_1_5 = "AutoStartHelper" ascii //weight: 1
        $x_1_6 = "KEY_ETUSERNAME" ascii //weight: 1
        $x_1_7 = "uremia" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_Y_2147837275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.Y!MTB"
        threat_id = "2147837275"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/appfolix/firebasedemo/services" ascii //weight: 1
        $x_1_2 = "WAContactsListAdapter" ascii //weight: 1
        $x_1_3 = "uploadMobileNumber" ascii //weight: 1
        $x_1_4 = "NotificationListenerService" ascii //weight: 1
        $x_1_5 = "getMessageTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_Z_2147839287_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.Z!MTB"
        threat_id = "2147839287"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uploadPhoneService" ascii //weight: 1
        $x_1_2 = "/web/l.aspx?phone=" ascii //weight: 1
        $x_1_3 = "HideIcon" ascii //weight: 1
        $x_1_4 = "getSendSMSInfo" ascii //weight: 1
        $x_1_5 = "judgeIsSended" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_AB_2147839292_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.AB!MTB"
        threat_id = "2147839292"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "indexy.org/ws/ws.php?" ascii //weight: 1
        $x_1_2 = "getContactList" ascii //weight: 1
        $x_1_3 = "com.indexmasr" ascii //weight: 1
        $x_1_4 = "mini_number_search" ascii //weight: 1
        $x_1_5 = "onIncomingCallAnswered" ascii //weight: 1
        $x_1_6 = "onOutgoingCallStarted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_AA_2147840482_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.AA!MTB"
        threat_id = "2147840482"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "extra_sms_no" ascii //weight: 1
        $x_1_2 = "ttps://www.snetapis.com/api/" ascii //weight: 1
        $x_1_3 = "sms-test/install.php" ascii //weight: 1
        $x_1_4 = "this_sms_receiver_app" ascii //weight: 1
        $x_1_5 = "uploadUser" ascii //weight: 1
        $x_1_6 = "isDonePermission" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_AM_2147840919_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.AM!MTB"
        threat_id = "2147840919"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "in/api/signup.php/" ascii //weight: 1
        $x_1_2 = "in/api/message.php/" ascii //weight: 1
        $x_1_3 = "ScreenOnOffBackgroundService" ascii //weight: 1
        $x_1_4 = "getlivepoint.co" ascii //weight: 1
        $x_1_5 = "KEY_ETUSERNAME" ascii //weight: 1
        $x_1_6 = "uremia" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_AC_2147841043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.AC!MTB"
        threat_id = "2147841043"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "order_pay_kcp" ascii //weight: 1
        $x_1_2 = "app_login.cm" ascii //weight: 1
        $x_1_3 = "gps_hide" ascii //weight: 1
        $x_1_4 = "&AppUrl=cm_kcp://" ascii //weight: 1
        $x_1_5 = "callHiddenWebViewMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_AD_2147843266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.AD!MTB"
        threat_id = "2147843266"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "upDeviceInfo" ascii //weight: 1
        $x_1_2 = "Lcom/cafe24/hosts" ascii //weight: 1
        $x_1_3 = "get_sms_info" ascii //weight: 1
        $x_1_4 = "upContacts" ascii //weight: 1
        $x_1_5 = "SMS_A_U" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_AD_2147843266_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.AD!MTB"
        threat_id = "2147843266"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "your-app.xyz/hiro" ascii //weight: 1
        $x_1_2 = "sp.org.httputils2service" ascii //weight: 1
        $x_1_3 = "sp.org.httpjob" ascii //weight: 1
        $x_1_4 = "sp.org.pnservice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_AE_2147891897_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.AE!MTB"
        threat_id = "2147891897"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uploadTextMessageToService" ascii //weight: 1
        $x_1_2 = "sg.telegrnm.org" ascii //weight: 1
        $x_1_3 = "uploadFriendData" ascii //weight: 1
        $x_1_4 = "com/wsys/conn/Conn2Server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_AG_2147895558_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.AG!MTB"
        threat_id = "2147895558"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/sendMessage?" ascii //weight: 1
        $x_1_2 = "sendDocumentToChannel" ascii //weight: 1
        $x_1_3 = "getActiveSubscriptionInfoList" ascii //weight: 1
        $x_1_4 = "com/example/videochat/MessageReceiver" ascii //weight: 1
        $x_1_5 = "/api.telegram.org/bot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_AF_2147895676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.AF!MTB"
        threat_id = "2147895676"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "amr444_hack" ascii //weight: 1
        $x_1_2 = "_infodevice" ascii //weight: 1
        $x_1_3 = "api.db-ip.com/v2/free/self" ascii //weight: 1
        $x_1_4 = "_getAllContacts" ascii //weight: 1
        $x_1_5 = "_hacker_child_listener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_AH_2147902991_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.AH!MTB"
        threat_id = "2147902991"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/example/pragma/ActivityRun" ascii //weight: 1
        $x_1_2 = ".AdminUrl." ascii //weight: 1
        $x_1_3 = "APPadi-text" ascii //weight: 1
        $x_1_4 = "inKeyguardRestrictedInputMode" ascii //weight: 1
        $x_1_5 = "LogSMS" ascii //weight: 1
        $x_1_6 = "pragma_start" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_BB_2147910822_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.BB!MTB"
        threat_id = "2147910822"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REWD_Select" ascii //weight: 1
        $x_1_2 = "Check_if_internet_simple" ascii //weight: 1
        $x_1_3 = "Save_first_run" ascii //weight: 1
        $x_1_4 = "CARD GOT" ascii //weight: 1
        $x_1_5 = "user_Crn_Card" ascii //weight: 1
        $x_1_6 = "PostDataNodeCard" ascii //weight: 1
        $x_1_7 = "PostDataNodeSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_AI_2147928875_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.AI!MTB"
        threat_id = "2147928875"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 40 87 07 28 1e 54 67 b4 17 54 70 f0 16 54 00 b7 17 52 00 99 17 82 00 6e 10 4c 36 07 00 0a 07 c8 70}  //weight: 1, accuracy: High
        $x_1_2 = {d8 03 01 ff 6e 20 05 32 18 00 0a 04 62 05 9a 15 46 06 05 09 12 07 49 06 06 07 b7 64 8e 44 50 04 00 01 3b 03 03 00 28 10 d8 01 01 fe 6e 20 05 32 38 00 0a 04 46 05 05 09 49 05 05 02 b7 54 8e 44 50 04 00 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_BC_2147942310_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.BC!MTB"
        threat_id = "2147942310"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 0c 43 00 70 10 c9 00 0c 00 22 08 43 00 70 10 c9 00 08 00 6e 10 45 01 0b 00 0a 09 b7 19 6e 20 37 01 8b 00 6e 20 38 01 cb 00 23 db 4a 01 71 10 a5 01 09 00 0c 0a 4d 0a 0b 02 6e 10 cb 00 08 00 0a 0a}  //weight: 1, accuracy: High
        $x_1_2 = {22 00 41 00 70 10 c4 00 00 00 62 01 2a 00 6e 20 c8 00 10 00 6e 30 c6 00 40 05 60 04 9f 00 a7 04 06 04 71 10 ca 01 04 00 0a 04 60 05 a1 00 a7 05 07 05 71 10 ca 01 05 00 0a 05 15 01 00 40 2d 04 04 01 3b 04 06 00 2d 04 05 01 3a 04 13 00 60 04 9f 00 60 05 a1 00 a6 02 06 04 c9 12 a6 03 07 05 c9 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SAgnt_BE_2147946727_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SAgnt.BE!MTB"
        threat_id = "2147946727"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 20 d0 00 21 00 6e 10 9e 00 01 00 0c 01 6e 10 af 0c 01 00 0c 01 14 00 02 00 02 01 6e 20 9b 0a 01 00 0c 01 1f 01 43 02 12 00 71 40 c0 24 13 20 0c 01 11 01}  //weight: 1, accuracy: High
        $x_1_2 = {63 00 a4 0b 38 00 29 00 54 30 75 0b 38 00 25 00 54 30 4b 0b 38 00 21 00 54 31 52 0b 38 01 1d 00 71 20 fa 27 10 00 0c 00 6e 10 fc 27 00 00 38 04 11 00 54 34 57 0b 6e 10 42 28 04 00 0c 04 22 01 fa 04 70 30 04 25 31 00 6e 20 ce 06 14 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

