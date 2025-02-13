rule TrojanSpy_AndroidOS_InfoStealer_BH_2147755804_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.BH!MTB"
        threat_id = "2147755804"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DZ.Eagle.Master.main" ascii //weight: 2
        $x_1_2 = "anywheresoftware.b4a.remotelogger.RemoteLogger" ascii //weight: 1
        $x_1_3 = "Bridge logger not enabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_A_2147759376_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.A!MTB"
        threat_id = "2147759376"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "sendMessageBy_CMD_TROJAN_CONNECT" ascii //weight: 3
        $x_1_2 = "CMD_TROJAN_INFO" ascii //weight: 1
        $x_1_3 = "getCallRecord" ascii //weight: 1
        $x_1_4 = "getBrowserData" ascii //weight: 1
        $x_1_5 = "chmod 777 -R \\data\\data" ascii //weight: 1
        $x_1_6 = "screencap -p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_InfoStealer_B_2147759380_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.B!MTB"
        threat_id = "2147759380"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/thread/SMSRecordThread;" ascii //weight: 1
        $x_1_2 = "/msc/manageCMDLine;" ascii //weight: 1
        $x_1_3 = "fetch_cpu_info" ascii //weight: 1
        $x_1_4 = "getAllSmss" ascii //weight: 1
        $x_1_5 = "getEmailsByContentId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_D_2147767162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.D!MTB"
        threat_id = "2147767162"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/upload/snapshotupload.shtml" ascii //weight: 1
        $x_1_2 = "/api_phonebook.shtml" ascii //weight: 1
        $x_1_3 = "/api_calllog.shtml" ascii //weight: 1
        $x_1_4 = "getCallLogURL" ascii //weight: 1
        $x_1_5 = "getUploadSmsXML" ascii //weight: 1
        $x_1_6 = "uploadContacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_E_2147768898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.E!MTB"
        threat_id = "2147768898"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/tsfsatsag/" ascii //weight: 2
        $x_1_2 = "queryContactPhoneNumber" ascii //weight: 1
        $x_1_3 = "encryptPassword" ascii //weight: 1
        $x_1_4 = "sms_str" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_InfoStealer_G_2147770468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.G!MTB"
        threat_id = "2147770468"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lsys/power/sys/IncomingSms;" ascii //weight: 1
        $x_1_2 = "Lsys/power/sys/AutoStartUp;" ascii //weight: 1
        $x_1_3 = {0c 6f 64 4e 6f 74 69 63 65 2e 74 78 74}  //weight: 1, accuracy: High
        $x_1_4 = "content://browser/bookmarks" ascii //weight: 1
        $x_1_5 = "/public/recoording.wav" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_H_2147771591_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.H!MTB"
        threat_id = "2147771591"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/saku/app/po;" ascii //weight: 1
        $x_1_2 = "/api/zhuan_bo" ascii //weight: 1
        $x_1_3 = "callDurationStr" ascii //weight: 1
        $x_1_4 = "sms_str" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_H_2147771591_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.H!MTB"
        threat_id = "2147771591"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Lcom/test/uploadcontact" ascii //weight: 5
        $x_2_2 = "content://sms/raw" ascii //weight: 2
        $x_1_3 = "hideApp" ascii //weight: 1
        $x_1_4 = "addressList" ascii //weight: 1
        $x_1_5 = "SMSObserver" ascii //weight: 1
        $x_1_6 = "MSGUploaded" ascii //weight: 1
        $x_1_7 = "/JYSystem/restInt/collect/postData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_InfoStealer_K_2147773828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.K!MTB"
        threat_id = "2147773828"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lnet/axel/app/serses/" ascii //weight: 1
        $x_1_2 = "install_non_market_apps" ascii //weight: 1
        $x_1_3 = "SMS_Reccording" ascii //weight: 1
        $x_1_4 = "com.android.settings:id/left_button" ascii //weight: 1
        $x_1_5 = "OUTGOING_WHATSAPP_CALL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_L_2147774197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.L!MTB"
        threat_id = "2147774197"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/example/dat/a8andoserverx/" ascii //weight: 2
        $x_1_2 = "/InterceptCall;" ascii //weight: 1
        $x_1_3 = "/Fake;" ascii //weight: 1
        $x_1_4 = ".app.apk" ascii //weight: 1
        $x_1_5 = "/DCIM/.fdat" ascii //weight: 1
        $x_1_6 = "setComponentEnabledSetting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_InfoStealer_N_2147776182_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.N!MTB"
        threat_id = "2147776182"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "liveCallHistory" ascii //weight: 1
        $x_1_2 = "getThirdAppList" ascii //weight: 1
        $x_1_3 = "deleteCallLogById" ascii //weight: 1
        $x_1_4 = "startLiveRecord" ascii //weight: 1
        $x_1_5 = "sendSMS" ascii //weight: 1
        $x_1_6 = "callsList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_P_2147778681_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.P!MTB"
        threat_id = "2147778681"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/update/system/important/callrecord/" ascii //weight: 2
        $x_1_2 = "/whatsapp/GetWhatsData;" ascii //weight: 1
        $x_1_3 = "MessageWhatsModel" ascii //weight: 1
        $x_1_4 = "MessengerMessageModel" ascii //weight: 1
        $x_1_5 = "StartCommandFromonStartCommand" ascii //weight: 1
        $x_1_6 = "loadAllByDateAndConversation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_InfoStealer_Q_2147779099_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.Q!MTB"
        threat_id = "2147779099"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/api/Phone/CallLog" ascii //weight: 1
        $x_1_2 = "/api/Phone/DelApk" ascii //weight: 1
        $x_1_3 = "hk_date" ascii //weight: 1
        $x_1_4 = "asyncCallOut" ascii //weight: 1
        $x_1_5 = "/SmsInfo;" ascii //weight: 1
        $x_1_6 = "/CallInService;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_SB_2147779734_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.SB!MTB"
        threat_id = "2147779734"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qrcode/back/newcxx" ascii //weight: 1
        $x_1_2 = "quitadoporra" ascii //weight: 1
        $x_1_3 = "ConexaoCentral.php" ascii //weight: 1
        $x_1_4 = "/TelephonyInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_AS_2147780412_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.AS!MTB"
        threat_id = "2147780412"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NumCorespondent::" ascii //weight: 1
        $x_1_2 = "DeviceIMEI=" ascii //weight: 1
        $x_1_3 = "USE_URL_SMS" ascii //weight: 1
        $x_1_4 = "Obnilim rid" ascii //weight: 1
        $x_1_5 = "Incoming SMS fixed" ascii //weight: 1
        $x_1_6 = "SELECT _id, msgdata, sended FROM messages WHERE sended=0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_R_2147781459_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.R!MTB"
        threat_id = "2147781459"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "spy_call_number" ascii //weight: 1
        $x_1_2 = "sync_key_logger" ascii //weight: 1
        $x_1_3 = "sync_installed_apps" ascii //weight: 1
        $x_1_4 = "sync_browser_history" ascii //weight: 1
        $x_1_5 = "call_recording_method" ascii //weight: 1
        $x_1_6 = "hideApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_T_2147786261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.T!MTB"
        threat_id = "2147786261"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PermChecActivity." ascii //weight: 1
        $x_1_2 = "CmdSender.cmd_cnt():- " ascii //weight: 1
        $x_1_3 = "m_loco_db.db" ascii //weight: 1
        $x_1_4 = "sp_key_remote_ip" ascii //weight: 1
        $x_1_5 = "spkeyuuid" ascii //weight: 1
        $x_1_6 = "gemtool.sytes.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_GK_2147796310_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.GK!MTB"
        threat_id = "2147796310"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com.test.accessibility.MyAccessibilityService" ascii //weight: 1
        $x_1_2 = "crypto.trustapp.ui.wallets.activity.ExportPhraseActivity" ascii //weight: 1
        $x_1_3 = "performGlobalAction" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-32] 2f 61 70 69 2f 72 65 73 74 2f}  //weight: 1, accuracy: Low
        $x_1_5 = "api.telegram.org/bot" ascii //weight: 1
        $x_1_6 = "monitor your activity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_U_2147819355_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.U!MTB"
        threat_id = "2147819355"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 72 61 74 6a 73 [0-2] 2f 54 6f 6f 6c 73 2f 52 75 6e 55 74 69 6c 3b}  //weight: 2, accuracy: Low
        $x_2_2 = "Lme/everything/providers/" ascii //weight: 2
        $x_1_3 = "getCallLog" ascii //weight: 1
        $x_1_4 = "getSMS" ascii //weight: 1
        $x_1_5 = "getAllApps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_InfoStealer_W_2147826797_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.W!MTB"
        threat_id = "2147826797"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 77 65 62 70 72 6f 6a 65 63 74 [0-2] 2f 44 6f 77 6e 6c 6f 61 64 43 6f 6d 70 6c 65 74 65 52 65 63 65 69 76 65 72 3b}  //weight: 1, accuracy: Low
        $x_1_2 = "/index.php/Api/Public/add_address_book" ascii //weight: 1
        $x_1_3 = "sendContactToServer" ascii //weight: 1
        $x_1_4 = "uploadMessageAboveL" ascii //weight: 1
        $x_1_5 = "/h5?plat=android" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_InfoStealer_X_2147833377_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/InfoStealer.X!MTB"
        threat_id = "2147833377"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.cao.webcamera" ascii //weight: 1
        $x_1_2 = "ynb.gzse7en.com" ascii //weight: 1
        $x_1_3 = "/servlet/GetMessage" ascii //weight: 1
        $x_1_4 = "/servlet/SendMassageJSON" ascii //weight: 1
        $x_1_5 = "/servlet/UploadImage" ascii //weight: 1
        $x_1_6 = "/servlet/ContactsUpload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

