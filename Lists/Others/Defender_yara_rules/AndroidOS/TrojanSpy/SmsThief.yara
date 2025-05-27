rule TrojanSpy_AndroidOS_SmsThief_A_2147757208_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.A!MTB"
        threat_id = "2147757208"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "btoolsRun" ascii //weight: 2
        $x_2_2 = "http://%s:%d/%s?%s" ascii //weight: 2
        $x_1_3 = "getSmsFromPhone" ascii //weight: 1
        $x_1_4 = "SmsObserver" ascii //weight: 1
        $x_1_5 = "monserver" ascii //weight: 1
        $x_1_6 = "phonemsg" ascii //weight: 1
        $x_1_7 = "CODE_READ_SMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_B_2147759929_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.B!MTB"
        threat_id = "2147759929"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Lcom/ApkEditors/HackingTelegram/IncomingSms" ascii //weight: 3
        $x_1_2 = "getDisplayMessageBody" ascii //weight: 1
        $x_1_3 = "debuggerPackageName" ascii //weight: 1
        $x_1_4 = "senderNum:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_D_2147767821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.D!MTB"
        threat_id = "2147767821"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Creating textSms to be send !" ascii //weight: 1
        $x_1_2 = "web.me.com" ascii //weight: 1
        $x_1_3 = "Send Calls log" ascii //weight: 1
        $x_1_4 = "checkEmailSms" ascii //weight: 1
        $x_1_5 = "PhoneLocator/Pro_version" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_D_2147767821_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.D!MTB"
        threat_id = "2147767821"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "aHR0cDovL2FwaXNlcnZlci56emZ5cC5jb206MjA5NS9hcGk=" ascii //weight: 2
        $x_2_2 = "Lcom/kb534/ekstvn/net/entity/CallLogEntity;" ascii //weight: 2
        $x_1_3 = "?type=incomingOnCall" ascii //weight: 1
        $x_1_4 = "/Android/Sma/Log" ascii //weight: 1
        $x_1_5 = "getSmsType" ascii //weight: 1
        $x_1_6 = "getSaler_code" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_E_2147767841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.E!MTB"
        threat_id = "2147767841"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/test/sms/HeadlessSmsSendService;" ascii //weight: 1
        $x_1_2 = "/sms/SmsListener;" ascii //weight: 1
        $x_1_3 = "/sms.php" ascii //weight: 1
        $x_1_4 = "incoming message" ascii //weight: 1
        $x_1_5 = "getOriginatingAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_G_2147771381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.G!MTB"
        threat_id = "2147771381"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/byl/sms/SmSApplication;" ascii //weight: 1
        $x_1_2 = "uploadSmSMethod" ascii //weight: 1
        $x_1_3 = "SMS_UP" ascii //weight: 1
        $x_1_4 = ".com/api/index/sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_H_2147773291_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.H!MTB"
        threat_id = "2147773291"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api.telegram.org/bot" ascii //weight: 1
        $x_1_2 = "battryrealrat" ascii //weight: 1
        $x_1_3 = "allapp.zip" ascii //weight: 1
        $x_1_4 = "allsms.zip" ascii //weight: 1
        $x_1_5 = "/sendallsms" ascii //weight: 1
        $x_1_6 = "ultra_hideicon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_K_2147774349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.K!MTB"
        threat_id = "2147774349"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "realrat/" ascii //weight: 2
        $x_1_2 = "_fuck" ascii //weight: 1
        $x_1_3 = "_uploadsucess" ascii //weight: 1
        $x_1_4 = "PhoneSms" ascii //weight: 1
        $x_1_5 = "SMSInterceptor" ascii //weight: 1
        $x_1_6 = "getDisplayMessageBody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_K_2147774349_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.K!MTB"
        threat_id = "2147774349"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/psiphon3/firebasemessaging;" ascii //weight: 2
        $x_2_2 = "Lcom/spinter/uploadfilephp/" ascii //weight: 2
        $x_1_3 = "/panel.php?uploadsms=" ascii //weight: 1
        $x_1_4 = "/phone/SmsWrapper" ascii //weight: 1
        $x_1_5 = "/Sms.txt" ascii //weight: 1
        $x_1_6 = "hideAppIcon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_L_2147775980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.L!MTB"
        threat_id = "2147775980"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/realspy/" ascii //weight: 2
        $x_2_2 = "/realrat/" ascii //weight: 2
        $x_1_3 = "smstocontacts" ascii //weight: 1
        $x_1_4 = "hideapk" ascii //weight: 1
        $x_1_5 = "contacts.txt" ascii //weight: 1
        $x_1_6 = "SMSInterceptor" ascii //weight: 1
        $x_1_7 = "post_data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_L_2147775980_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.L!MTB"
        threat_id = "2147775980"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/Kryptosms;" ascii //weight: 2
        $x_1_2 = "/AutoService;" ascii //weight: 1
        $x_1_3 = "/Lukas" ascii //weight: 1
        $x_1_4 = "findAccessibilityNodeInfosByViewId" ascii //weight: 1
        $x_1_5 = "getDisplayMessageBody" ascii //weight: 1
        $x_1_6 = "performAction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_M_2147777629_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.M!MTB"
        threat_id = "2147777629"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lir/siqe/holo/connect;" ascii //weight: 2
        $x_2_2 = "Lir/siqe/holo/MyReceiver;" ascii //weight: 2
        $x_1_3 = ".php?phone=" ascii //weight: 1
        $x_1_4 = "getMessageBody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_M_2147777629_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.M!MTB"
        threat_id = "2147777629"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 69 72 2f 70 61 72 64 61 6b 68 ?? 2f 53 6d 73 24 53 65 6e 64 50 6f 73 74 52 65 71 75 65 73 74 3b}  //weight: 1, accuracy: Low
        $x_1_2 = "Ladrt/ADRTSender;" ascii //weight: 1
        $x_1_3 = "SmsReceiver" ascii //weight: 1
        $x_1_4 = "getDataHttpUrlConnection" ascii //weight: 1
        $x_1_5 = "getDisplayMessageBody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_N_2147778541_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.N!MTB"
        threat_id = "2147778541"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 69 64 65 6f 73 6f 75 6e 64 2e 76 69 70 [0-5] 2f 4a 59 53 79 73 74 65 6d 2f 72 65 73 74 49 6e 74 2f 63 6f 6c 6c 65 63 74 2f 70 6f 73 74 4d 73 67 44 61 74 61}  //weight: 2, accuracy: Low
        $x_1_2 = "/collect/postData" ascii //weight: 1
        $x_1_3 = "uploadMSG" ascii //weight: 1
        $x_1_4 = "hideApp" ascii //weight: 1
        $x_1_5 = "uploadContacts" ascii //weight: 1
        $x_1_6 = "com/baidu/locass/utils" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_C_2147786560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.C!MTB"
        threat_id = "2147786560"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "snedPhone" ascii //weight: 1
        $x_1_2 = "simulateKeystroke" ascii //weight: 1
        $x_1_3 = "mailMsg" ascii //weight: 1
        $x_1_4 = "getContactNameFromPhoneNum" ascii //weight: 1
        $x_1_5 = "getSendServerSms" ascii //weight: 1
        $x_1_6 = "sendKeyDownUpSync" ascii //weight: 1
        $x_1_7 = "smtp.qq.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_O_2147794125_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.O"
        threat_id = "2147794125"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "startSendLocal" ascii //weight: 2
        $x_1_2 = "AxQPCzIBACgXLQIRAx4CBAQYU1dO" ascii //weight: 1
        $x_1_3 = "AwE+DA4CHQ8NDjgGAh0=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_A_2147795444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.A"
        threat_id = "2147795444"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/api/msgstore?task=" ascii //weight: 1
        $x_1_2 = "&type=Inbox&dateformat=" ascii //weight: 1
        $x_1_3 = "getAllSms" ascii //weight: 1
        $x_1_4 = "getPerm" ascii //weight: 1
        $x_1_5 = "/SmsListener;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_S_2147797093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.S!MTB"
        threat_id = "2147797093"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getSmsInPhone" ascii //weight: 1
        $x_1_2 = "set_call_recorder" ascii //weight: 1
        $x_1_3 = "get_all_calls_and_send" ascii //weight: 1
        $x_1_4 = "send_deceive_sms" ascii //weight: 1
        $x_1_5 = "execRootCmdSilent" ascii //weight: 1
        $x_1_6 = "Rec_Sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_T_2147806217_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.T!MTB"
        threat_id = "2147806217"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 6f 6d 2f 68 65 6c 70 64 65 76 2f [0-8] 71 75 69 63 6b 73 75 70 70 6f 72 74 2f 72 65 63 65 69 76 65 72 2f 53 6d 73 52 65 63 65 69 76 65 72 3b}  //weight: 1, accuracy: Low
        $x_1_2 = "requestSmsPermission" ascii //weight: 1
        $x_1_3 = "hideApp" ascii //weight: 1
        $x_1_4 = "fetchLogo" ascii //weight: 1
        $x_1_5 = "autoLaunchVivo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AC_2147807993_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AC"
        threat_id = "2147807993"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "extractMessages" ascii //weight: 1
        $x_1_2 = "DataRequest(sender_no=" ascii //weight: 1
        $x_1_3 = "getmobilno" ascii //weight: 1
        $x_1_4 = "9118919678" ascii //weight: 1
        $x_1_5 = "com/helpdev/kycform" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AP_2147809159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AP!MTB"
        threat_id = "2147809159"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "extractMessages" ascii //weight: 1
        $x_1_2 = "DataRequest(sender_no=" ascii //weight: 1
        $x_1_3 = "save_sms.php" ascii //weight: 1
        $x_1_4 = "9118919678" ascii //weight: 1
        $x_1_5 = "Lbr/com/helpdev/kycform" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_F_2147809997_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.F!MTB"
        threat_id = "2147809997"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "save_sms.php" ascii //weight: 1
        $x_2_2 = "extractMessages" ascii //weight: 2
        $x_1_3 = "REQUEST_CODE_SMS_PERMISSION" ascii //weight: 1
        $x_3_4 = "br/com/helpdev/kycform/receiver/SMSReceiver" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_F_2147809997_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.F!MTB"
        threat_id = "2147809997"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/psiphon3/firebasemessaging" ascii //weight: 2
        $x_1_2 = "getLastSms" ascii //weight: 1
        $x_1_3 = "getAllSMS" ascii //weight: 1
        $x_1_4 = "getcontacts" ascii //weight: 1
        $x_1_5 = "smcontacts" ascii //weight: 1
        $x_1_6 = "hideAppIcon" ascii //weight: 1
        $x_1_7 = "iran-pot.tk/sigh" ascii //weight: 1
        $x_1_8 = "test.test" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_Q_2147814081_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.Q!MTB"
        threat_id = "2147814081"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/upd/task.php" ascii //weight: 1
        $x_1_2 = "send_sms_number" ascii //weight: 1
        $x_1_3 = "sendSMSOnThePhoneBook" ascii //weight: 1
        $x_1_4 = "reportWichDataTaskInject" ascii //weight: 1
        $x_1_5 = "/upd/inj.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_W_2147814082_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.W!MTB"
        threat_id = "2147814082"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET_ALL_PHO_AND_SENTSMS_MSG" ascii //weight: 1
        $x_1_2 = "contact_id = " ascii //weight: 1
        $x_1_3 = "IsUnistaller" ascii //weight: 1
        $x_1_4 = "CONTROL_NUMBER" ascii //weight: 1
        $x_1_5 = "isActiveNetworkMetered" ascii //weight: 1
        $x_1_6 = "sent_sms_action" ascii //weight: 1
        $x_1_7 = "IsFirstRun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_J_2147815318_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.J!MTB"
        threat_id = "2147815318"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "create.php" ascii //weight: 1
        $x_1_2 = "deleteChat" ascii //weight: 1
        $x_1_3 = "setpush.php" ascii //weight: 1
        $x_1_4 = "messagebot.php" ascii //weight: 1
        $x_1_5 = "https://edalat.ir-46549.xyz" ascii //weight: 1
        $x_1_6 = "pay.php?name=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_P_2147815320_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.P!MTB"
        threat_id = "2147815320"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NotificationMonitorService" ascii //weight: 1
        $x_1_2 = "/api/uploads/simsave" ascii //weight: 1
        $x_1_3 = "collectDeviceInfo" ascii //weight: 1
        $x_1_4 = "uploadSms" ascii //weight: 1
        $x_1_5 = "getAllPhotoInfo" ascii //weight: 1
        $x_1_6 = "smsInPhone" ascii //weight: 1
        $x_1_7 = "uploads/photosave" ascii //weight: 1
        $x_1_8 = "-deleteSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_V_2147815375_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.V!MTB"
        threat_id = "2147815375"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "trackInstall" ascii //weight: 1
        $x_1_2 = "uploadmsg" ascii //weight: 1
        $x_1_3 = "SmsInfo" ascii //weight: 1
        $x_1_4 = "monserver" ascii //weight: 1
        $x_1_5 = "upload_screenshot" ascii //weight: 1
        $x_1_6 = "getTaskDetailInfo" ascii //weight: 1
        $x_1_7 = "getCouponHistoryMoreData" ascii //weight: 1
        $x_1_8 = "getFistForwardInfo" ascii //weight: 1
        $x_1_9 = "ForwardDetailActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_X_2147815434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.X!MTB"
        threat_id = "2147815434"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "save user info" ascii //weight: 1
        $x_1_2 = "phoneinfoService" ascii //weight: 1
        $x_1_3 = "MyContactDetail" ascii //weight: 1
        $x_1_4 = "saveAppInfo" ascii //weight: 1
        $x_1_5 = "phoneinfo.race.fzm.com.phoneinfo" ascii //weight: 1
        $x_1_6 = "GetPhoneList" ascii //weight: 1
        $x_1_7 = "getSendSmsName" ascii //weight: 1
        $x_1_8 = "ttp://47.92.30.96:8089/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_R_2147815583_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.R!MTB"
        threat_id = "2147815583"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.sanaapk" ascii //weight: 1
        $x_1_2 = "com.MarsMan" ascii //weight: 1
        $x_1_3 = "getLastSms" ascii //weight: 1
        $x_1_4 = "hideAppIcon" ascii //weight: 1
        $x_1_5 = "test.test" ascii //weight: 1
        $x_1_6 = "smcontacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_Y_2147815895_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.Y!MTB"
        threat_id = "2147815895"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 6f 6d 2f 68 65 6c 70 64 65 76 2f [0-16] 73 75 70 70 6f 72 74 2f 75 74 69 6c 73 2f 4d 79 53 65 72 76 69 63 65 3b}  //weight: 1, accuracy: Low
        $x_1_2 = "save_sms.php" ascii //weight: 1
        $x_1_3 = {09 73 6d 73 5f 72 65 63 76 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "sendor_no" ascii //weight: 1
        $x_1_5 = "/controller/api/common/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_QB_2147818012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.QB!MTB"
        threat_id = "2147818012"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SecretActivity" ascii //weight: 1
        $x_1_2 = {36 32 0c 00 22 00 84 00 [0-5] 08 02 50 00 6e 10 [0-5] 00 00 0c 00 11 00 49 04 05 03 dc 00 03 05 2b 00 16 00 00 00 01 10 b7 40 8e 00 50 00 05 03 d8 00 03 01 01 03 [0-5] 13 00 23 00 [0-5] 12 30 [0-5] 13 00 69 00 [0-5] 01 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_U_2147818192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.U!MTB"
        threat_id = "2147818192"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendMessageSilently" ascii //weight: 1
        $x_1_2 = "uploadMessageSilently" ascii //weight: 1
        $x_1_3 = "handleSmsIntercepted" ascii //weight: 1
        $x_1_4 = "getPhoneNumber" ascii //weight: 1
        $x_1_5 = "getSmsInPhone" ascii //weight: 1
        $x_1_6 = "sendTelephoneInfos" ascii //weight: 1
        $x_1_7 = "getMailTelephoneInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_BB_2147818682_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BB!MTB"
        threat_id = "2147818682"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "org.android.sys" ascii //weight: 1
        $x_1_2 = "tsystem_update.apk" ascii //weight: 1
        $x_1_3 = "apps.darkclub.net/request/" ascii //weight: 1
        $x_1_4 = "UPDATE_PATTERNS" ascii //weight: 1
        $x_1_5 = "removeActiveAdmin" ascii //weight: 1
        $x_1_6 = "getMessageBody" ascii //weight: 1
        $x_1_7 = "847297460902" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AA_2147818874_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AA!MTB"
        threat_id = "2147818874"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/api/uploads/apisms" ascii //weight: 1
        $x_1_2 = "/com/local/LocalMessage" ascii //weight: 1
        $x_1_3 = "com/zhy/http/okhttp/" ascii //weight: 1
        $x_1_4 = "content://sms/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_Z_2147818961_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.Z!MTB"
        threat_id = "2147818961"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/app/dwurianzs23" ascii //weight: 1
        $x_1_2 = "SendSmsActivity" ascii //weight: 1
        $x_1_3 = "durianking.mydiveapp.online" ascii //weight: 1
        $x_1_4 = "android_asset/ipayFPX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_Z_2147818961_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.Z!MTB"
        threat_id = "2147818961"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "has_send_phone_info" ascii //weight: 1
        $x_1_2 = "last_delete_sms_time" ascii //weight: 1
        $x_1_3 = "has_send_contacts" ascii //weight: 1
        $x_1_4 = "com/phone/stop/activity" ascii //weight: 1
        $x_1_5 = "has_send_message" ascii //weight: 1
        $x_1_6 = "send_email_pwd" ascii //weight: 1
        $x_1_7 = "has_delete_message" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_Y_2147819825_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.Y"
        threat_id = "2147819825"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {61 70 69 5f 73 70 61 [0-32] 2f 61 70 69 5f 65 73 70 61 6e 6f 6c 2f 61 70 69 2e 70 68 70 3f 73 69 64 3d 25 31 24 73 26 73 6d 73 3d 25 32 24 73}  //weight: 10, accuracy: Low
        $x_10_2 = "online/app_abc771_2sfacslfffcs2/" ascii //weight: 10
        $x_10_3 = "_888a/api/api.php?get_tax_currency" ascii //weight: 10
        $x_1_4 = "Please allow SMS before proceed or reinstall the app" ascii //weight: 1
        $x_1_5 = "getMessageBody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_AB_2147820483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AB!MTB"
        threat_id = "2147820483"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rtuiopbhsda.com" ascii //weight: 1
        $x_1_2 = "SNSDBBSJN/ISSASDS" ascii //weight: 1
        $x_1_3 = "loadurl" ascii //weight: 1
        $x_1_4 = "getMessageBody" ascii //weight: 1
        $x_1_5 = "com/example/svi/ReceiverClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_CA_2147821602_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.CA!MTB"
        threat_id = "2147821602"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.twu.info" ascii //weight: 2
        $x_1_2 = "SmsObserver" ascii //weight: 1
        $x_1_3 = "getAllContacts" ascii //weight: 1
        $x_1_4 = "getSmsInPhone" ascii //weight: 1
        $x_1_5 = "Csinfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_AF_2147822340_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AF!MTB"
        threat_id = "2147822340"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ADS_MAIN_INTERSTITIAL_INTERVAL" ascii //weight: 1
        $x_1_2 = "sgdurianking.mydiveapp.online" ascii //weight: 1
        $x_1_3 = "RemoteConfig" ascii //weight: 1
        $x_1_4 = "SmsSendService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AF_2147822340_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AF!MTB"
        threat_id = "2147822340"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/uera/er/SmSutils;" ascii //weight: 1
        $x_1_2 = "isServiceRun" ascii //weight: 1
        $x_1_3 = "sendSMS" ascii //weight: 1
        $x_1_4 = "setComponentEnabledSetting" ascii //weight: 1
        $x_1_5 = "Ladrt/ADRTSender" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_I_2147823625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.I!MTB"
        threat_id = "2147823625"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/system/SMSReceiver$HTTPTask;" ascii //weight: 1
        $x_1_2 = "sendViaSMS" ascii //weight: 1
        $x_1_3 = "SEND_TYPE_HTTP_THEN_SMS" ascii //weight: 1
        $x_1_4 = "abortBroadcast" ascii //weight: 1
        $x_1_5 = "performAction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AG_2147826954_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AG!MTB"
        threat_id = "2147826954"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/soapi/getmsgs" ascii //weight: 1
        $x_1_2 = "JHINMsgReceiver" ascii //weight: 1
        $x_1_3 = "startGetMsgs" ascii //weight: 1
        $x_1_4 = "InboxToServerThread" ascii //weight: 1
        $x_1_5 = "sendSMS2Long" ascii //weight: 1
        $x_1_6 = "SMS_CHANGE_SERVER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AE_2147827595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AE!MTB"
        threat_id = "2147827595"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com.app.islandtravel" ascii //weight: 1
        $x_1_2 = "app/islandtravel/activities" ascii //weight: 1
        $x_1_3 = "yellowssss.online" ascii //weight: 1
        $x_1_4 = "getMessageBody" ascii //weight: 1
        $x_1_5 = {61 70 69 5f 73 70 61 [0-32] 2f 61 70 69 5f 65 73 70 61 6e 6f 6c 2f 61 70 69 2e 70 68 70 3f 73 69 64 3d 25 31 24 73 26 73 6d 73 3d 25 32 24 73}  //weight: 1, accuracy: Low
        $x_1_6 = "javax/inject/provider;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AH_2147830155_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AH!MTB"
        threat_id = "2147830155"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/app/midcleaning/MyReciever" ascii //weight: 1
        $x_1_2 = "maid4u" ascii //weight: 1
        $x_1_3 = {3a 2f 2f 79 2d [0-5] 2e 6f 6e 6c 69 6e 65}  //weight: 1, accuracy: Low
        $x_1_4 = "pass=app168&cmd=sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AI_2147831238_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AI!MTB"
        threat_id = "2147831238"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/app/bestpay/MyReciever" ascii //weight: 1
        $x_1_2 = "SendSmsActivity" ascii //weight: 1
        $x_1_3 = "sgbx.online" ascii //weight: 1
        $x_1_4 = "SmsSendService" ascii //weight: 1
        $x_1_5 = "?pass=app168&cmd=sms&sid=%1$s&sms=%2$s" ascii //weight: 1
        $x_1_6 = "SMSBroadcastReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AJ_2147832431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AJ!MTB"
        threat_id = "2147832431"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yonainorman.site/SNSDBBSJN/ISSASDS" ascii //weight: 1
        $x_1_2 = "/cover.html?dID=" ascii //weight: 1
        $x_1_3 = "com.example.kosi" ascii //weight: 1
        $x_1_4 = "getMessageBody" ascii //weight: 1
        $x_1_5 = "GetMobileDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AL_2147833055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AL!MTB"
        threat_id = "2147833055"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSOBServer" ascii //weight: 1
        $x_1_2 = "snedContacts" ascii //weight: 1
        $x_1_3 = "BadSMSReceiver" ascii //weight: 1
        $x_1_4 = "BANK_TOP_CHECK_TIME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AL_2147833055_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AL!MTB"
        threat_id = "2147833055"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getSmsInPhone" ascii //weight: 1
        $x_1_2 = "POST_CONTACT" ascii //weight: 1
        $x_1_3 = "SMS_URI_ALL" ascii //weight: 1
        $x_1_4 = "getAllContacts" ascii //weight: 1
        $x_1_5 = "phone/transfer/receiver/SmsReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AK_2147833809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AK!MTB"
        threat_id = "2147833809"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "arrayOfSmsMessage" ascii //weight: 1
        $x_1_2 = "MesageAPPLication" ascii //weight: 1
        $x_1_3 = "sendSms" ascii //weight: 1
        $x_1_4 = "resgister" ascii //weight: 1
        $x_1_5 = "smsHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AN_2147835683_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AN!MTB"
        threat_id = "2147835683"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/servletContact" ascii //weight: 1
        $x_1_2 = "queryInboxSms" ascii //weight: 1
        $x_1_3 = "inboxContactList" ascii //weight: 1
        $x_1_4 = "setComponentEnabledSetting" ascii //weight: 1
        $x_1_5 = "smsList" ascii //weight: 1
        $x_1_6 = "getForwardNumber" ascii //weight: 1
        $x_10_7 = "Lcom/pro_new/www/PhoneService" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_AO_2147842590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AO!MTB"
        threat_id = "2147842590"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSPrapti" ascii //weight: 1
        $x_1_2 = "geopo.at" ascii //weight: 1
        $x_1_3 = "com/cloudganga/android/cgfinder" ascii //weight: 1
        $x_1_4 = "TRACKCMD" ascii //weight: 1
        $x_1_5 = "parseSMSCmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AQ_2147842917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AQ!MTB"
        threat_id = "2147842917"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UploadSmsFile" ascii //weight: 1
        $x_1_2 = "com/execulator/sockettest" ascii //weight: 1
        $x_1_3 = "getSMSLogs" ascii //weight: 1
        $x_1_4 = "getClipboardText" ascii //weight: 1
        $x_1_5 = "AllSms.txt" ascii //weight: 1
        $x_1_6 = "sendSmsPermissionCode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AS_2147843798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AS!MTB"
        threat_id = "2147843798"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "www.comnetorginfo.com" ascii //weight: 1
        $x_1_2 = "SmsReceiverActivity" ascii //weight: 1
        $x_1_3 = "com/internet/webchrome" ascii //weight: 1
        $x_1_4 = {64 61 74 61 2f 69 6e 73 74 61 6c 6c [0-4] 2e 70 68 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AQ_2147850580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AQ"
        threat_id = "2147850580"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.neonet.app.reader" ascii //weight: 5
        $x_5_2 = "Lcom/cannav/cuasimodo/jumper/somalia;" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AU_2147852242_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AU!MTB"
        threat_id = "2147852242"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uploadMessages" ascii //weight: 1
        $x_1_2 = "MessageReceiverListener" ascii //weight: 1
        $x_1_3 = "HttpLoggingInterceptor" ascii //weight: 1
        $x_1_4 = "co/techive/dmart/SMSReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AV_2147893465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AV!MTB"
        threat_id = "2147893465"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoHideReceiver" ascii //weight: 1
        $x_1_2 = "com/rat/logger/SmsReceiver" ascii //weight: 1
        $x_1_3 = "SendContactToServer" ascii //weight: 1
        $x_1_4 = "appsmslogger" ascii //weight: 1
        $x_1_5 = "SmmsDatabase" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AW_2147895557_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AW!MTB"
        threat_id = "2147895557"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/main.php?get=sms" ascii //weight: 1
        $x_1_2 = "oncesms.txt" ascii //weight: 1
        $x_1_3 = "SmsInterceptor" ascii //weight: 1
        $x_1_4 = "com.saderat.sina" ascii //weight: 1
        $x_1_5 = "/saderat.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AX_2147900572_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AX!MTB"
        threat_id = "2147900572"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "insert_messages.php" ascii //weight: 1
        $x_1_2 = "is_fwd_sms" ascii //weight: 1
        $x_1_3 = "com/callgirlsservices" ascii //weight: 1
        $x_1_4 = "call_click" ascii //weight: 1
        $x_1_5 = "bypass_200" ascii //weight: 1
        $x_1_6 = "send_sms_to" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_AZ_2147902071_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.AZ!MTB"
        threat_id = "2147902071"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/lymors/lulumoney" ascii //weight: 1
        $x_1_2 = "MySmsService" ascii //weight: 1
        $x_1_3 = "Lmra App" ascii //weight: 1
        $x_1_4 = "getNationality" ascii //weight: 1
        $x_1_5 = "SmsModel" ascii //weight: 1
        $x_1_6 = "getDateOfBirth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_BC_2147902990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BC!MTB"
        threat_id = "2147902990"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.example.remoteapp" ascii //weight: 2
        $x_1_2 = "telegram.org/bot6" ascii //weight: 1
        $x_1_3 = "extractMessages" ascii //weight: 1
        $x_1_4 = "SMSReceiver.kt" ascii //weight: 1
        $x_1_5 = "RatMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_BD_2147905721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BD!MTB"
        threat_id = "2147905721"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/sendMessage?chat_id=" ascii //weight: 1
        $x_1_2 = "/sendDocument" ascii //weight: 1
        $x_1_3 = "Contacts.txt" ascii //weight: 1
        $x_1_4 = "shd/ske/DebugActivity" ascii //weight: 1
        $x_1_5 = "/api.telegram.org/bot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_BE_2147909920_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BE!MTB"
        threat_id = "2147909920"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "readAndUploadSMS" ascii //weight: 1
        $x_1_2 = "uploadDataToFirestore" ascii //weight: 1
        $x_1_3 = "/MessagesService" ascii //weight: 1
        $x_1_4 = "uploadMessages" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_BF_2147910826_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BF!MTB"
        threat_id = "2147910826"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.dhruv.smsrecevier" ascii //weight: 5
        $x_1_2 = "/admin/no.php" ascii //weight: 1
        $x_1_3 = "/admin/phone.json" ascii //weight: 1
        $x_1_4 = "getDisplayOriginatingAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_BG_2147912000_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BG!MTB"
        threat_id = "2147912000"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "registerSmsReceiver" ascii //weight: 1
        $x_1_2 = "SmsForwardingService" ascii //weight: 1
        $x_1_3 = "_uploadDataToFirebase" ascii //weight: 1
        $x_1_4 = "SmsService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_BJ_2147914074_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BJ!MTB"
        threat_id = "2147914074"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.cstsprtapphdn.amssmmss" ascii //weight: 1
        $x_1_2 = "mss.techshow.cloud/sbiapp" ascii //weight: 1
        $x_1_3 = "/admindata.txt" ascii //weight: 1
        $x_1_4 = "ReceiveSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_BK_2147919019_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BK!MTB"
        threat_id = "2147919019"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com/mgb/safe" ascii //weight: 2
        $x_1_2 = "PhoneRecordUtil" ascii //weight: 1
        $x_1_3 = "BlackApplication" ascii //weight: 1
        $x_1_4 = "getSmsInPhone" ascii //weight: 1
        $x_1_5 = "SmsWriteOpUtil" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SmsThief_BH_2147923346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BH!MTB"
        threat_id = "2147923346"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isDestinationAllowed" ascii //weight: 1
        $x_1_2 = "com/asdfintoasdf/agoogleplayservicesrinrole" ascii //weight: 1
        $x_1_3 = "RESULT_UNSUPPORTED_ART_VERSION" ascii //weight: 1
        $x_1_4 = "ContentInfoCompat" ascii //weight: 1
        $x_1_5 = "RESULT_INSTALL_SKIP_FILE_SUCCESS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_BL_2147923679_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BL!MTB"
        threat_id = "2147923679"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/senter/autocamera" ascii //weight: 1
        $x_1_2 = "DrawCaptureRect" ascii //weight: 1
        $x_1_3 = "MPUEntity" ascii //weight: 1
        $x_1_4 = "KEY_DBM_LEVEL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_BO_2147929262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BO!MTB"
        threat_id = "2147929262"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/complaintmanager" ascii //weight: 1
        $x_1_2 = "ForwardMessageOnMobile" ascii //weight: 1
        $x_1_3 = "sendMessageToServer" ascii //weight: 1
        $x_1_4 = "callApiToSendSmsOnServerEvery15Min" ascii //weight: 1
        $x_1_5 = "SmsProcessService" ascii //weight: 1
        $x_1_6 = "addallmessege" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_BP_2147934905_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BP!MTB"
        threat_id = "2147934905"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 00 3d 00 70 10 6c 00 00 00 1a 01 81 00 6e 20 6f 00 10 00 0c 00 71 00 71 00 00 00 0c 01 6e 10 72 00 01 00 0b 01 6e 30 6d 00 10 02 0c 00 6e 10 70 00 00 00 0c 00 1a 01 c3 00 71 20 1a 00 01 00 6e 10 7a 00 05 00 0a 00 38 00 09 00 6e 10 79 00 05 00 0c 00 6e 10 7b 00 00 00 0e 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 10 2c 00 02 00 22 00 41 00 70 10 74 00 00 00 5b 20 1e 00 1a 00 c4 00 5b 20 1c 00 22 00 3d 00 70 10 6c 00 00 00 62 01 04 00 6e 20 6f 00 10 00 0c 00 1a 01 0f 00 6e 20 6f 00 10 00 0c 00 62 01 0b 00 6e 20 6f 00 10 00 0c 00 71 00 14 00 00 00 0c 01 6e 20 6e 00 10 00 0c 00 6e 10 70 00 00 00 0c 00 5b 20 1f 00 22 00 26 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_BM_2147935653_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BM!MTB"
        threat_id = "2147935653"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 10 00 0c 00 54 21 1a 00 71 10 ?? 00 01 00 0c 01 6e 20 ?? 00 10 00 0c 00 6e 10 ?? 00 00 00 0c 00 5b 20 1c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {22 00 08 00 54 31 03 00 6e 10 40 00 01 00 0c 01 1c 02 30 00 70 30 08 00 10 02 54 31 03 00 6e 20 4c 00 01 00 54 31 03 00 6e 10 3f 00 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_BN_2147935654_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BN!MTB"
        threat_id = "2147935654"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/example/smsreae" ascii //weight: 1
        $x_1_2 = {0a 00 0c 0a 1a 00 ?? 80 71 20 83 08 0a 00 0c 0a 5b 9a c7 4b 6e 10 e7 02 0b 00 0c 0a 1a 00 ?? 7f 6e 20 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsThief_BQ_2147942308_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsThief.BQ!MTB"
        threat_id = "2147942308"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 57 35 76 35 01 46 07 04 06 1f 07 48 00 71 10 16 00 07 00 0c 07 4d 07 05 06 46 07 05 06 6e 10 18 00 07 00 0c 07 46 08 05 06 6e 10 17 00 08 00 0c 08 1a 09 14 00 1a 0a 0e 00 6e 30 69 00 98 0a 0c 09 1a 0a 11 00 6e 30 69 00 a9 02 0c 0a}  //weight: 1, accuracy: High
        $x_1_2 = {13 10 01 00 46 0f 0f 10 6e 20 6a 00 2d 00 0c 10 13 11 02 00 46 10 10 11 08 16 10 00 6e 10 6b 00 0e 00 0c 10 77 01 65 00 10 00 0a 10 02 17 10 00 08 18 00 00 14 00 03 d9 00 00 08 19 02 00 02 02 17 00 33 02 5c 00 71 00 14 00 00 00 0c 10 13 12 00 00 13 14 00 00 13 15 00 00 08 11 0f 00 08 13 16 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

