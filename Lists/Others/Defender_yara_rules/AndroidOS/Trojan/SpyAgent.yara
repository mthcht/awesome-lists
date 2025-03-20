rule Trojan_AndroidOS_SpyAgent_A_2147788183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.A!MTB"
        threat_id = "2147788183"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "KEY_PHONE_IMEI" ascii //weight: 3
        $x_2_2 = "com/spyss/Wwwww" ascii //weight: 2
        $x_1_3 = "ALL_SYNC_CONTACTS" ascii //weight: 1
        $x_1_4 = "syncCallLogs()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SpyAgent_A_2147793158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.A"
        threat_id = "2147793158"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "url_telegram_redirect" ascii //weight: 5
        $x_5_2 = "send_message" ascii //weight: 5
        $x_5_3 = "hidden_app" ascii //weight: 5
        $x_5_4 = "sender_threader" ascii //weight: 5
        $x_5_5 = "New Device Opened Application:" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_XYZ_2147796198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.XYZ"
        threat_id = "2147796198"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setSmsbody" ascii //weight: 1
        $x_1_2 = "Lcom/amap/api/location/APSService" ascii //weight: 1
        $x_1_3 = "cloud/WebActivity" ascii //weight: 1
        $x_1_4 = "markHostNameFailed" ascii //weight: 1
        $x_1_5 = "ipv6 request is" ascii //weight: 1
        $x_1_6 = "yiyi.qi" ascii //weight: 1
        $x_1_7 = "!!!finish-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_C_2147798665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.C"
        threat_id = "2147798665"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "template_phishing_url" ascii //weight: 1
        $x_1_2 = "phishing_appname" ascii //weight: 1
        $x_1_3 = "smslist" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_D_2147798812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.D"
        threat_id = "2147798812"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/perfect/communicateapp/LocalMessage" ascii //weight: 1
        $x_1_2 = "setSmsbody" ascii //weight: 1
        $x_1_3 = "KY29tLmhleXRhcC5vcGVuaWQuSU9wZW5JRA" ascii //weight: 1
        $x_1_4 = "markHostNameFailed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_BH_2147805913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.BH"
        threat_id = "2147805913"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendSmsAb" ascii //weight: 1
        $x_1_2 = "uploadPhoneNumbers" ascii //weight: 1
        $x_1_3 = "Lcom/tram/mj/" ascii //weight: 1
        $x_1_4 = "fillApps preferences.appsInstalled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_SG_2147806216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.SG!MTB"
        threat_id = "2147806216"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://img.tfq0.cn:90" ascii //weight: 1
        $x_1_2 = "myTel" ascii //weight: 1
        $x_1_3 = "myMsgs" ascii //weight: 1
        $x_1_4 = "myInfo" ascii //weight: 1
        $x_1_5 = "myModel" ascii //weight: 1
        $x_1_6 = "javascript:javaCallJs()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_AD_2147807205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.AD"
        threat_id = "2147807205"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "callsList" ascii //weight: 1
        $x_1_2 = "Deleting Conversation Please wait" ascii //weight: 1
        $x_1_3 = "Uploading Video" ascii //weight: 1
        $x_1_4 = "Please provide the permission to work properly" ascii //weight: 1
        $x_1_5 = "aHR0cDovL3d3dy5pd2lsbHNlY3VyZXlvdS5jb20v" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_E_2147828872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.E!MTB"
        threat_id = "2147828872"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/sqisland/android/swipe_image_viewer" ascii //weight: 1
        $x_1_2 = "SendHelloPacket" ascii //weight: 1
        $x_1_3 = "getAllFilesOfDirUploadToLive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_N_2147829874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.N!MTB"
        threat_id = "2147829874"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "screenUnLockEvent" ascii //weight: 1
        $x_1_2 = "isScrlocked" ascii //weight: 1
        $x_1_3 = "serviceInFill" ascii //weight: 1
        $x_1_4 = "registerSCReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_B_2147831479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.B!MTB"
        threat_id = "2147831479"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSSTATUS" ascii //weight: 1
        $x_1_2 = "PhonecallReceiver" ascii //weight: 1
        $x_1_3 = "SMSBroadcastReceiver" ascii //weight: 1
        $x_1_4 = "ScreenStatus" ascii //weight: 1
        $x_1_5 = "n_onStartCommand" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_C_2147831784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.C!MTB"
        threat_id = "2147831784"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/spy/uploadMobileContacts" ascii //weight: 2
        $x_1_2 = "/uploadMobileCallLogs" ascii //weight: 1
        $x_1_3 = "/uploadMobileSmss" ascii //weight: 1
        $x_1_4 = "/uploadMobileGps" ascii //weight: 1
        $x_1_5 = "/api/v1/goods/detail/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SpyAgent_E_2147835802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.E"
        threat_id = "2147835802"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hp_state.php?telnum=" ascii //weight: 2
        $x_2_2 = "Lcom/doai/diaw/Stunning;" ascii //weight: 2
        $x_2_3 = "http://38.64.92.98:8989" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_F_2147836540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.F"
        threat_id = "2147836540"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GeckoContacts" ascii //weight: 2
        $x_2_2 = "DATABASE_PATH_EASY_LOAD_NUMBER" ascii //weight: 2
        $x_2_3 = "DATABASE_PATH_AW_SMS" ascii //weight: 2
        $x_2_4 = "WA_MESSAGES_US/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_G_2147836625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.G"
        threat_id = "2147836625"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "lastsmsone" ascii //weight: 2
        $x_2_2 = "fullinfoone" ascii //weight: 2
        $x_2_3 = "com.exception.rat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_I_2147836688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.I"
        threat_id = "2147836688"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bAppDataUser" ascii //weight: 2
        $x_2_2 = "ApiController/adds" ascii //weight: 2
        $x_2_3 = "Lcom/example/test/IRequestService;" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_K_2147837402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.K"
        threat_id = "2147837402"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dvpt.com:81" ascii //weight: 1
        $x_1_2 = "quene_exector_cover" ascii //weight: 1
        $x_1_3 = "YiDuListActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_K_2147837402_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.K"
        threat_id = "2147837402"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "checkIsSmsPermissionGrant" ascii //weight: 2
        $x_2_2 = "UniFeService" ascii //weight: 2
        $x_2_3 = "SMS_PERMISSION_PUSH" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_K_2147837402_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.K"
        threat_id = "2147837402"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "please config FTP server" ascii //weight: 1
        $x_1_2 = "no baseloc data" ascii //weight: 1
        $x_1_3 = "email msg type error" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_L_2147837410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.L"
        threat_id = "2147837410"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Onenter_onEnter" ascii //weight: 1
        $x_1_2 = "OnExit_ctxArry" ascii //weight: 1
        $x_1_3 = "tjf.rxiw.gswr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_L_2147837410_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.L"
        threat_id = "2147837410"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sg1.mall-base-app" ascii //weight: 2
        $x_2_2 = "MainSmsActivityStart" ascii //weight: 2
        $x_2_3 = "Native_RESULT_KEY" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_M_2147841525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.M"
        threat_id = "2147841525"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "readSMSBox" ascii //weight: 2
        $x_2_2 = "Hello there, welcome to reverse shell of" ascii //weight: 2
        $x_2_3 = "takepic \\d" ascii //weight: 2
        $x_2_4 = "stopVideo123" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_N_2147841713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.N"
        threat_id = "2147841713"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/hosts/device/c_s_m;" ascii //weight: 2
        $x_2_2 = "com/api/getlogintoken" ascii //weight: 2
        $x_2_3 = "SMS_A_U" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_O_2147843610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.O"
        threat_id = "2147843610"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PRIMARY_ACCESSTOKEN" ascii //weight: 2
        $x_2_2 = "PLUGINDEXDOWN" ascii //weight: 2
        $x_2_3 = "wecoin/updateStateService" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_P_2147846266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.P"
        threat_id = "2147846266"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "getAppKeylog" ascii //weight: 2
        $x_2_2 = "DeviceInfos/upNode" ascii //weight: 2
        $x_2_3 = "/readme_now.txt" ascii //weight: 2
        $x_2_4 = "clearAppKeylog" ascii //weight: 2
        $x_2_5 = "getSMSAllList" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_Q_2147847253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.Q"
        threat_id = "2147847253"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GetInBoxMSG_Filter_spent" ascii //weight: 2
        $x_2_2 = "RegisterReceiverSms" ascii //weight: 2
        $x_2_3 = "Save_first_run" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_S_2147848111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.S"
        threat_id = "2147848111"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "checkdozeeFeermi" ascii //weight: 2
        $x_2_2 = "isnotiservRuuntt" ascii //weight: 2
        $x_2_3 = "getInnstaling" ascii //weight: 2
        $x_2_4 = "faketakeScreenshotssssss" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_JH_2147851330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.JH"
        threat_id = "2147851330"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "doMobileBeat" ascii //weight: 2
        $x_2_2 = "getPhoneNumChangeNum" ascii //weight: 2
        $x_2_3 = "getPhoneNumCome" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_HF_2147851549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.HF"
        threat_id = "2147851549"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AucioRecorderActivity" ascii //weight: 2
        $x_2_2 = "Server_IsRunClipboard" ascii //weight: 2
        $x_2_3 = "createFullScreenNotificationWithMessage" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_U_2147852113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.U"
        threat_id = "2147852113"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ceshi enter main222" ascii //weight: 1
        $x_1_2 = "ceshi enter home" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_U_2147852113_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.U"
        threat_id = "2147852113"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GET_LAST_SMS_INBOX" ascii //weight: 2
        $x_2_2 = "NO_SILENT_SMS" ascii //weight: 2
        $x_2_3 = "GET_ALL_SMS_SENT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_V_2147852573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.V"
        threat_id = "2147852573"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&oncesms=" ascii //weight: 2
        $x_2_2 = "&action=sms&network=" ascii //weight: 2
        $x_2_3 = "_set_act_enabled" ascii //weight: 2
        $x_2_4 = "&action=offstatusdis" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_W_2147888194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.W"
        threat_id = "2147888194"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "startVideo \\d" ascii //weight: 1
        $x_1_2 = "--  Front Camera" ascii //weight: 1
        $x_1_3 = "takepic \\d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_W_2147888194_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.W"
        threat_id = "2147888194"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "onuscreates" ascii //weight: 2
        $x_2_2 = "phisdatasetup" ascii //weight: 2
        $x_2_3 = "/apkfromhelltoyouforthis" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_AY_2147891386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.AY"
        threat_id = "2147891386"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SPACE_W_CONV" ascii //weight: 2
        $x_2_2 = "wht_chat" ascii //weight: 2
        $x_2_3 = "SPACE_NOTIFYT" ascii //weight: 2
        $x_2_4 = "getCrecon" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_AR_2147892071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.AR"
        threat_id = "2147892071"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Task1UniqueName" ascii //weight: 2
        $x_2_2 = "com/notnull/release/Gizmo" ascii //weight: 2
        $x_2_3 = "notnull/release/WebV" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_BJ_2147895224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.BJ"
        threat_id = "2147895224"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ACTIVITY_RE_PERMISSION" ascii //weight: 2
        $x_2_2 = "ACTIVITY_IGNORE_ACCESSIBILITY" ascii //weight: 2
        $x_2_3 = "ACTIVITY_MAIN_FINISH_TASK" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_RU_2147896326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.RU"
        threat_id = "2147896326"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PoM_adm" ascii //weight: 2
        $x_2_2 = "SmsSendService1" ascii //weight: 2
        $x_2_3 = "app/goR00t" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_X_2147899119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.X"
        threat_id = "2147899119"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&action=importcontact" ascii //weight: 2
        $x_2_2 = "/up_file.php?response=true&id=" ascii //weight: 2
        $x_2_3 = "&action=offstatusen" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_NS_2147912797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.NS"
        threat_id = "2147912797"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Intent_Service_check_test" ascii //weight: 2
        $x_2_2 = "check_update?ver=abcd" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_AQ_2147919637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.AQ"
        threat_id = "2147919637"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "wwwhaha/homogePneous" ascii //weight: 2
        $x_2_2 = "mymf/FullscreenActivity" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_AL_2147921645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.AL"
        threat_id = "2147921645"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WakeLockExampleAppTag1" ascii //weight: 2
        $x_2_2 = "com.example.dat.a8andoserverx.SHUTDOWN" ascii //weight: 2
        $x_2_3 = "Start Record kokokokoko" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_AI_2147921646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.AI"
        threat_id = "2147921646"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ScreenGetPicUse" ascii //weight: 2
        $x_2_2 = "AllowPrims14-startX:" ascii //weight: 2
        $x_2_3 = "ScreenRecorderEncodeUse" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_Y_2147923349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.Y!MTB"
        threat_id = "2147923349"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IMyAidlInterface" ascii //weight: 1
        $x_1_2 = "BBconstantYY" ascii //weight: 1
        $x_1_3 = "/api/upload/app-icon" ascii //weight: 1
        $x_1_4 = "outError.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_AV_2147934498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.AV"
        threat_id = "2147934498"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "collectAndSendContacts" ascii //weight: 2
        $x_2_2 = "collectAndSendCallLog" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_AE_2147934500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.AE"
        threat_id = "2147934500"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CREATE TABLE worm_status (id INTEGER PRIMARY KEY AUTOINCREMENT,is_active INTEGER,call_to TEXT,frequency INTEGER,dialog_title TEXT,dialog_message TEXT)" ascii //weight: 2
        $x_2_2 = "TABLE_NAME_WORMSTATUS" ascii //weight: 2
        $x_2_3 = "RegisterWormData" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_SpyAgent_AZ_2147936555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyAgent.AZ"
        threat_id = "2147936555"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "w8notftyhk/MainActivity$collectAndSendInitialData$1" ascii //weight: 2
        $x_2_2 = "w8notftyhk/AppService" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

