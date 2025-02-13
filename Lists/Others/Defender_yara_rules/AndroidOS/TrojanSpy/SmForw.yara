rule TrojanSpy_AndroidOS_SmForw_A_2147753140_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.A"
        threat_id = "2147753140"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegDPMActivity" ascii //weight: 1
        $x_1_2 = "CallStateListner" ascii //weight: 1
        $x_1_3 = "end call!!" ascii //weight: 1
        $x_1_4 = "getsmsblockstate.php?telnum=" ascii //weight: 1
        $x_1_5 = "/PreodicService;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_A_2147754434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.A!MTB"
        threat_id = "2147754434"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "send_phonlist" ascii //weight: 1
        $x_1_2 = "bank.sbank.activity" ascii //weight: 1
        $x_1_3 = "/get_sms_command" ascii //weight: 1
        $x_1_4 = "hana.apk" ascii //weight: 1
        $x_1_5 = "webcash.wooribank" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_B_2147792920_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.B!MTB"
        threat_id = "2147792920"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendPoke" ascii //weight: 1
        $x_1_2 = "getTelCompany" ascii //weight: 1
        $x_1_3 = "hp_getsmsblockstate.php?telnum" ascii //weight: 1
        $x_1_4 = "index.php?type=receivesms&telnum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_B_2147792920_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.B!MTB"
        threat_id = "2147792920"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hp_getsmsblockstate.php" ascii //weight: 1
        $x_1_2 = "receivesms&telnum" ascii //weight: 1
        $x_1_3 = "tel_blockcallstate" ascii //weight: 1
        $x_1_4 = "getPhoneNumber" ascii //weight: 1
        $x_1_5 = "doScanNet" ascii //weight: 1
        $x_1_6 = {4c 63 6f 6d [0-23] 43 6f 6e 6e 4d 61 63 68 69 6e 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_C_2147814452_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.C!MTB"
        threat_id = "2147814452"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.jshymedia.jshypay.plus.AppPlus" ascii //weight: 1
        $x_1_2 = "jarData.jar" ascii //weight: 1
        $x_1_3 = "AutoAns_Send" ascii //weight: 1
        $x_1_4 = "sys_sended" ascii //weight: 1
        $x_1_5 = "andr/uploadlog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_D_2147814987_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.D!MTB"
        threat_id = "2147814987"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hp_state.php" ascii //weight: 1
        $x_1_2 = "index.php?type=join&telnum=" ascii //weight: 1
        $x_1_3 = "sendUserData" ascii //weight: 1
        $x_1_4 = "hp_getsmsblockstate.php?telnum=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_F_2147826269_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.F!MTB"
        threat_id = "2147826269"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallLogger" ascii //weight: 1
        $x_1_2 = "INTERCEPT_SMS" ascii //weight: 1
        $x_1_3 = "com/phone/callcorexy" ascii //weight: 1
        $x_1_4 = "getUploadSmsCount" ascii //weight: 1
        $x_1_5 = "deleteAllCallRecordHistory" ascii //weight: 1
        $x_1_6 = "INTERCEPT_ALL_PHONE" ascii //weight: 1
        $x_1_7 = "mMyCallContentObserver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_G_2147829346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.G!MTB"
        threat_id = "2147829346"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.defender.plugin.FirstRunnable" ascii //weight: 1
        $x_1_2 = "defender_plugin.jar" ascii //weight: 1
        $x_1_3 = ".stream|modt1" ascii //weight: 1
        $x_1_4 = "setComponentEnabledSetting" ascii //weight: 1
        $x_1_5 = "device_policy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_H_2147833092_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.H!MTB"
        threat_id = "2147833092"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ContactInfo" ascii //weight: 1
        $x_1_2 = "CHECK_OUTGOING_SMS" ascii //weight: 1
        $x_1_3 = "contact.txt" ascii //weight: 1
        $x_1_4 = "MonitorSMS" ascii //weight: 1
        $x_1_5 = "OutgoingSmsLogger" ascii //weight: 1
        $x_1_6 = "Lcom/android/secrettalk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_I_2147834161_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.I!MTB"
        threat_id = "2147834161"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/xinghai/sms" ascii //weight: 1
        $x_1_2 = {2e 63 6f 6d 2f [0-5] 2f 73 61 76 65 73 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_3 = "getMessagesFromIntent" ascii //weight: 1
        $x_1_4 = "getDisplayMessageBody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_K_2147839066_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.K!MTB"
        threat_id = "2147839066"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "usehost" ascii //weight: 1
        $x_1_2 = "/login.php" ascii //weight: 1
        $x_1_3 = "com/Copon/SMS" ascii //weight: 1
        $x_1_4 = "clService" ascii //weight: 1
        $x_1_5 = "sms.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_J_2147839485_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.J!MTB"
        threat_id = "2147839485"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsReceiverUrl" ascii //weight: 1
        $x_1_2 = "sentAdMessage" ascii //weight: 1
        $x_1_3 = "DoAfterReceiveMailListener" ascii //weight: 1
        $x_1_4 = "getAllHistoryCache" ascii //weight: 1
        $x_1_5 = "ReciveOneMail" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_L_2147841387_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.L!MTB"
        threat_id = "2147841387"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMS_BlockState" ascii //weight: 1
        $x_1_2 = "InsertContacts" ascii //weight: 1
        $x_1_3 = "answerRingingCall" ascii //weight: 1
        $x_1_4 = "hp_getsmsblockstate.php" ascii //weight: 1
        $x_1_5 = "index.php?type=receivesms&telnum=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_M_2147901461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.M!MTB"
        threat_id = "2147901461"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "injectAppSmsReceiver" ascii //weight: 1
        $x_1_2 = "getCurrentPhoneNumber" ascii //weight: 1
        $x_1_3 = {63 6f 6d 2f 6d 65 73 73 61 67 65 66 6f 72 77 61 72 64 ?? ?? 2f 63 75 73 74 6f 6d 65 72}  //weight: 1, accuracy: Low
        $x_1_4 = "injectAppRepository" ascii //weight: 1
        $x_1_5 = "forwardMessage" ascii //weight: 1
        $x_1_6 = "AppSmsReceiver_GeneratedInjector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_N_2147903258_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.N!MTB"
        threat_id = "2147903258"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/fde/gsActivity" ascii //weight: 1
        $x_1_2 = "ddMyWebActivity" ascii //weight: 1
        $x_1_3 = "hfCancelNoticeService" ascii //weight: 1
        $x_1_4 = "vgMainService" ascii //weight: 1
        $x_1_5 = "esMyApplication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SmForw_O_2147903259_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmForw.O!MTB"
        threat_id = "2147903259"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmForw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "edMyWebActivity" ascii //weight: 1
        $x_1_2 = "gdCancelNoticeService" ascii //weight: 1
        $x_1_3 = "dgMainService" ascii //weight: 1
        $x_1_4 = "ghsMyApplication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

