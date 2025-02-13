rule Trojan_AndroidOS_Smsthief_AM_2147816202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.AM"
        threat_id = "2147816202"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aggiorna-web.org/sms.php" ascii //weight: 1
        $x_1_2 = "message content" ascii //weight: 1
        $x_1_3 = "incoming message" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_2147816359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.sd"
        threat_id = "2147816359"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        info = "sd: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sms_recve" ascii //weight: 1
        $x_1_2 = "messafge" ascii //weight: 1
        $x_1_3 = "successfully registered" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_A_2147831271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.A"
        threat_id = "2147831271"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "?pass=app168&cmd=sms&sid=%1$s&sms=%2$s" ascii //weight: 2
        $x_2_2 = "//sgbx.online" ascii //weight: 2
        $x_2_3 = "MyReciever" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_B_2147831272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.B"
        threat_id = "2147831272"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "getClientAdvanced" ascii //weight: 2
        $x_2_2 = "com.easylinz.reload" ascii //weight: 2
        $x_2_3 = "phoneMgr" ascii //weight: 2
        $x_2_4 = "QuickResponseService$SmsReceiver" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_D_2147834610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.D"
        threat_id = "2147834610"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Discount 30%: (ilovered99) RM" ascii //weight: 1
        $x_1_2 = "?pass=app168&cmd=sms&sid=%1$s&sms=%2$s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_D_2147834610_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.D"
        threat_id = "2147834610"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "btnbeforpay" ascii //weight: 2
        $x_2_2 = "com.zeroone.divaraop.SplashActivityAlias" ascii //weight: 2
        $x_2_3 = "irdvsves.cf/respon.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_F_2147835028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.F"
        threat_id = "2147835028"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "findNodesByTextv2" ascii //weight: 1
        $x_1_2 = "_wifipolc_meth_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_F_2147835028_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.F"
        threat_id = "2147835028"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hibliss" ascii //weight: 2
        $x_2_2 = "apacheck notification message service" ascii //weight: 2
        $x_2_3 = "Lcom/shounakmulay/telephony/sms/IncomingSmsReceiver" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_G_2147835043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.G"
        threat_id = "2147835043"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "lydiateam.bal" ascii //weight: 2
        $x_2_2 = "_lydia_sendsms" ascii //weight: 2
        $x_2_3 = "getewayport.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_G_2147835043_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.G"
        threat_id = "2147835043"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/android/system/SystemService" ascii //weight: 2
        $x_2_2 = "AppDownloaderActivity" ascii //weight: 2
        $x_2_3 = "CheckTask" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_AR_2147838333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.AR!MTB"
        threat_id = "2147838333"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSOBServer" ascii //weight: 1
        $x_1_2 = "sendphone" ascii //weight: 1
        $x_1_3 = "sendwww" ascii //weight: 1
        $x_1_4 = "BadSMSReceiver" ascii //weight: 1
        $x_1_5 = "com/decryptstringmanager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Smsthief_F_2147840217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.F!MTB"
        threat_id = "2147840217"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendMessage?parse_mode=markdown&chat_id=" ascii //weight: 1
        $x_1_2 = "loket2-fastpay.online" ascii //weight: 1
        $x_1_3 = "com/example/myapplication" ascii //weight: 1
        $x_1_4 = "SendSMS" ascii //weight: 1
        $x_1_5 = "ReceiveSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Smsthief_P_2147852535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.P"
        threat_id = "2147852535"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MMSReceiverClass" ascii //weight: 1
        $x_1_2 = "SNSDBBSJN/ISSASDS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_P_2147852535_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.P"
        threat_id = "2147852535"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.appCommon.org" ascii //weight: 1
        $x_1_2 = "I,have Fucking Your " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_P_2147852535_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.P"
        threat_id = "2147852535"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsForwardingService" ascii //weight: 1
        $x_1_2 = "Error forwarding SMS body:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_P_2147852535_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.P"
        threat_id = "2147852535"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isPhoneMove tel:**21*121%23" ascii //weight: 1
        $x_1_2 = "sms client had changed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_P_2147852535_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.P"
        threat_id = "2147852535"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "myapplicatior/MainActivityAlias" ascii //weight: 2
        $x_2_2 = "rep_msgbody3" ascii //weight: 2
        $x_2_3 = "&text=*Aplikasi Terinstall di Perangkat :* _" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Smsthief_Y_2147853124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.Y"
        threat_id = "2147853124"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.prnc.hideicon" ascii //weight: 2
        $x_1_2 = "zxzxzxnotsend" ascii //weight: 1
        $x_1_3 = "upipindekh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_ER_2147890501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.ER"
        threat_id = "2147890501"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0123456879qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM" ascii //weight: 1
        $x_1_2 = "ElegantCryptoDe" ascii //weight: 1
        $x_1_3 = "KEY_MAX_SMS_TIME" ascii //weight: 1
        $x_1_4 = "%s/Xms/%s" ascii //weight: 1
        $x_1_5 = "xmsUser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_AJ_2147894345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.AJ"
        threat_id = "2147894345"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetAllSmsNotSendedYet" ascii //weight: 1
        $x_1_2 = "offlinesmsnumber" ascii //weight: 1
        $x_1_3 = "getAutohideafterseconds" ascii //weight: 1
        $x_1_4 = "UPDATE offlinesms set issend=1 where id = ?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsthief_AK_2147894346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsthief.AK"
        threat_id = "2147894346"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsthief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ContactSmsApplication" ascii //weight: 2
        $x_2_2 = "mehrab_notif_id" ascii //weight: 2
        $x_2_3 = "SimSmsApplication" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

