rule Trojan_AndroidOS_SpyBanker_X_2147794530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.X"
        threat_id = "2147794530"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "K_ALL_MESSAGE_UPLOADED" ascii //weight: 2
        $x_2_2 = "K_UP_CALL_INFO" ascii //weight: 2
        $x_2_3 = "K_APPS_LIST" ascii //weight: 2
        $x_2_4 = "K_SEND_WEB_USER_INFO" ascii //weight: 2
        $x_2_5 = "K_RECORD_MESSAGE" ascii //weight: 2
        $x_2_6 = "K_UP_LOCATION" ascii //weight: 2
        $x_2_7 = "K_CALL_CONNCTED" ascii //weight: 2
        $x_2_8 = "K_GIT_HOST" ascii //weight: 2
        $x_2_9 = "K_GIT_GET_HOST_TIMER_INFO" ascii //weight: 2
        $x_2_10 = "K_UP_MESSAGE_INFO" ascii //weight: 2
        $x_2_11 = "K_UP_CONTACT_INFO" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_AH_2147799576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.AH"
        threat_id = "2147799576"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setMalware" ascii //weight: 1
        $x_1_2 = "prating=" ascii //weight: 1
        $x_1_3 = "A message about something weird" ascii //weight: 1
        $x_1_4 = "text_sms_permission_required" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_B_2147828477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.B!MTB"
        threat_id = "2147828477"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cosmetiq.fl" ascii //weight: 1
        $x_1_2 = "SmsKitKatService" ascii //weight: 1
        $x_1_3 = "IncomeSMSActivity" ascii //weight: 1
        $x_1_4 = "bot_id" ascii //weight: 1
        $x_1_5 = "upload_sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_A_2147828583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.A!MTB"
        threat_id = "2147828583"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wipedata" ascii //weight: 1
        $x_1_2 = "fakepin_activity" ascii //weight: 1
        $x_1_3 = "createscreencaptureintent" ascii //weight: 1
        $x_1_4 = "contactsutils" ascii //weight: 1
        $x_1_5 = "smspush_br" ascii //weight: 1
        $x_1_6 = "credentials.java" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_D_2147830296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.D!MTB"
        threat_id = "2147830296"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DailReceiver" ascii //weight: 1
        $x_1_2 = "updateCallLog" ascii //weight: 1
        $x_1_3 = "PhoneStatReceiver" ascii //weight: 1
        $x_1_4 = "sendCallInfo" ascii //weight: 1
        $x_1_5 = "sendUserInfo" ascii //weight: 1
        $x_1_6 = "getCallNumberInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_C_2147832600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.C!MTB"
        threat_id = "2147832600"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ru/theft/hypothesize" ascii //weight: 1
        $x_1_2 = "AgencyOfficial" ascii //weight: 1
        $x_1_3 = "IBysu" ascii //weight: 1
        $x_1_4 = "quostpeopls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_B_2147834581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.B"
        threat_id = "2147834581"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/actividades;" ascii //weight: 2
        $x_2_2 = "unsentMsgs" ascii //weight: 2
        $x_2_3 = "Lcom/cannav/cuasimodo/jumper/somalia;" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_C_2147834864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.C"
        threat_id = "2147834864"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "000webhostapp.com/save_sms.php?phone=" ascii //weight: 2
        $x_2_2 = "REQ_CODE_PERMISSION_SEND_SMS" ascii //weight: 2
        $x_2_3 = "mysmsmanager" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_I_2147835436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.I"
        threat_id = "2147835436"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REQ_CODE_PERMISSION_RECEIVE_SMS" ascii //weight: 1
        $x_1_2 = "Lsrthk/pthk/smsforwarder/services" ascii //weight: 1
        $x_1_3 = "URL_ATM" ascii //weight: 1
        $x_1_4 = "Received SMS from" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_J_2147837411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.J"
        threat_id = "2147837411"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lsrthk/pthk/smsforwarder/services" ascii //weight: 1
        $x_1_2 = "REQ_CODE_PERMISSION_SEND_SMS" ascii //weight: 1
        $x_1_3 = "Sms_Forwarder.app.main" ascii //weight: 1
        $x_1_4 = "net.trices.webview" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_K_2147837468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.K"
        threat_id = "2147837468"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "save_sms0.php" ascii //weight: 4
        $x_2_2 = "Lcom/example/upi/SmsReceiver" ascii //weight: 2
        $x_2_3 = "Lcom/example/myapplication/SmsListner" ascii //weight: 2
        $x_2_4 = "Lcom/example/upi/SmsListner" ascii //weight: 2
        $x_2_5 = "com.study76547study.application.vidhiya.myapplication" ascii //weight: 2
        $x_2_6 = "/vidhiya/myapplication/SmsReciver" ascii //weight: 2
        $x_2_7 = "Lnet/trices/sms/" ascii //weight: 2
        $x_2_8 = "Lcom/abc898d/webmaster/SmsReceiver" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SpyBanker_L_2147837469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.L"
        threat_id = "2147837469"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getSmsServiceIntent" ascii //weight: 1
        $x_1_2 = "DataModelUserData(phone_number=" ascii //weight: 1
        $x_1_3 = "getUser_adhaar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_D_2147837549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.D"
        threat_id = "2147837549"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "000webhostapp.com/save_sms" ascii //weight: 2
        $x_2_2 = "S1m2s3R4e5c6e7i8v9e0r" ascii //weight: 2
        $x_2_3 = "C1o2n3s4t5a6n7t8s9" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_F_2147837628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.F"
        threat_id = "2147837628"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vnc_allow10" ascii //weight: 2
        $x_2_2 = "protect2020_str" ascii //weight: 2
        $x_2_3 = "schet_sws" ascii //weight: 2
        $x_2_4 = "sunset_cmd" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_E_2147840556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.E"
        threat_id = "2147840556"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "checkReadAndReceiveAndSendSms" ascii //weight: 1
        $x_1_2 = "checkCaptureMic" ascii //weight: 1
        $x_1_3 = "inspectorPrefs" ascii //weight: 1
        $x_1_4 = "checkCaptureCam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_AZ_2147840873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.AZ!MTB"
        threat_id = "2147840873"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6e 10 39 0d 05 00 0c 00 1a 01 12 e3 71 20 41 fe 10 00 20 01 3a 00 38 01 cc 00 1f 00 3a 00 22 01 c9 22 70 10 41 e8 01 00 1a 03 e3 6d 6e 20 4c e8 31 00 0c 01 62 03 b1 84 6e 10 6c e6 03 00 0c 03 6e 20 4c e8 31 00 0c 01 6e 20 4c e8 21 00 0c 01 6e 10 38 0d 05 00 0c 02 6e 20 4b e8 21 00 0c 01 13 02 0a 00 6e 20 44 e8 21 00 0c 01 6e 10 52 e8 01 00 0c 01 22 02 c9 22}  //weight: 2, accuracy: High
        $x_1_2 = "devil/sk/MainService" ascii //weight: 1
        $x_1_3 = "com/bankingsecurityinc/customers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SpyBanker_G_2147841197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.G"
        threat_id = "2147841197"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/bank12.php?m=Api&a=Sms&imsi=" ascii //weight: 2
        $x_2_2 = "zipNPKI" ascii //weight: 2
        $x_2_3 = "m=Api&a=Index&bank=" ascii //weight: 2
        $x_2_4 = "&recertpw=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_M_2147841439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.M"
        threat_id = "2147841439"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LseC/vqdjq/iuhlysui/IesnujIuhlysu" ascii //weight: 3
        $x_1_2 = "const_task_id_send_sms" ascii //weight: 1
        $x_1_3 = "receiverStatusSms" ascii //weight: 1
        $x_1_4 = "upd contact list" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SpyBanker_E_2147842140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.E!MTB"
        threat_id = "2147842140"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bitsolution.info/?odjasijdaosi" ascii //weight: 1
        $x_1_2 = "braziliankings.ddns.net/renew" ascii //weight: 1
        $x_1_3 = "service.webview.webkisz" ascii //weight: 1
        $x_1_4 = "load.php?hwid=" ascii //weight: 1
        $x_1_5 = "/mobileconfig.php" ascii //weight: 1
        $x_1_6 = "xqdtBupuiiqwu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_G_2147842143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.G!MTB"
        threat_id = "2147842143"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/jakedegivuwuwe/yewo" ascii //weight: 1
        $x_1_2 = "com/cisojemopatude/yazi/catozotu" ascii //weight: 1
        $x_1_3 = "callcapablephoneaccounts" ascii //weight: 1
        $x_1_4 = "send_log_injects" ascii //weight: 1
        $x_1_5 = "getclipdata" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_O_2147842423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.O"
        threat_id = "2147842423"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "instant-e-apply-campaign-page-idf-campaign-fix.xyz" ascii //weight: 2
        $x_2_2 = "bfhfhfrom" ascii //weight: 2
        $x_2_3 = "SmsWorder" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_S_2147848547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.S"
        threat_id = "2147848547"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HelloteacherService" ascii //weight: 2
        $x_2_2 = "isReqPermission" ascii //weight: 2
        $x_2_3 = "unlock_screen_gestures" ascii //weight: 2
        $x_2_4 = "screen_multi_task" ascii //weight: 2
        $x_2_5 = "api.sixmiss.com" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_T_2147848815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.T"
        threat_id = "2147848815"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "data_9/index_9.php" ascii //weight: 2
        $x_2_2 = "EXTRA_SMS_NO_9" ascii //weight: 2
        $x_2_3 = "SmsReceiverActivity_9" ascii //weight: 2
        $x_2_4 = "EXTRA_SMS_MESSAGE_9" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_Q_2147851355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.Q"
        threat_id = "2147851355"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PermisScreen" ascii //weight: 2
        $x_2_2 = "InternalCamBrowserScreen" ascii //weight: 2
        $x_2_3 = "AMSUnstopablle" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_R_2147853152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.R"
        threat_id = "2147853152"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sendNationalCode.php" ascii //weight: 2
        $x_2_2 = "/mellat/LActivity" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_JK_2147890030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.JK"
        threat_id = "2147890030"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "saxapi.easecare.sbs/api" ascii //weight: 2
        $x_2_2 = "cards/axapi/ServiceCommunicator" ascii //weight: 2
        $x_2_3 = "Adhar card is required is required" ascii //weight: 2
        $x_2_4 = "cards/axapi/SecondForm" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_AS_2147892644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.AS"
        threat_id = "2147892644"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "startMyAccessibilityService" ascii //weight: 2
        $x_2_2 = "onlyfans/NotifyListener" ascii //weight: 2
        $x_2_3 = "pesrmiss" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_NM_2147895642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.NM"
        threat_id = "2147895642"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "uploadImagesAndThenData" ascii //weight: 2
        $x_2_2 = "getImranPath" ascii //weight: 2
        $x_2_3 = "LoanSucessfully" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_JE_2147896769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.JE"
        threat_id = "2147896769"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ProfitFeedbackSender" ascii //weight: 2
        $x_2_2 = "SendFeedbackScript" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_AL_2147911032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.AL"
        threat_id = "2147911032"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "massagg/MainActivityAlias" ascii //weight: 2
        $x_2_2 = "google/massagg/SendSMS" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_AV_2147911034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.AV"
        threat_id = "2147911034"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "makeRequestForGettingDataFromServer" ascii //weight: 2
        $x_2_2 = "EXECUTION_TELEPHONY_RAT_COMMAND" ascii //weight: 2
        $x_2_3 = "makeGettingBalanceRequest" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_BV_2147911611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.BV"
        threat_id = "2147911611"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {26 74 65 78 74 3d f0 9d 97 95 f0 9d 97 b2 f0 9d 97 bf f0 9d 97 b5 f0 9d 97 ae f0 9d 98 80 f0 9d 97 b6 f0 9d 97 b9 20 f0 9d 97 a7 f0 9d 97 b2 f0 9d 97 bf f0 9d 97 b8 f0 9d 97 bc f0 9d 97 bb f0 9d 97 b2 f0 9d 97 b8 f0 9d 98 80 f0 9d 97 b6}  //weight: 2, accuracy: High
        $x_2_2 = "appjava/ReceiveSms" ascii //weight: 2
        $x_2_3 = "&text=Ditolak" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_W_2147913370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.W"
        threat_id = "2147913370"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OrgQueryStartTempDate" ascii //weight: 2
        $x_2_2 = "SendPhotoAlarmBroadcastReceiver" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyBanker_AY_2147916913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyBanker.AY"
        threat_id = "2147916913"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyBanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gateway/option_activity" ascii //weight: 2
        $x_2_2 = "incomingsmsgateway/SmsMainActivity" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

