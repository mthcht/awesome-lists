rule Trojan_AndroidOS_SAgent_P_2147809770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgent.P!MTB"
        threat_id = "2147809770"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_sendsms_child_listener" ascii //weight: 1
        $x_1_2 = "_infodevice" ascii //weight: 1
        $x_1_3 = "com/kaboos/vip" ascii //weight: 1
        $x_1_4 = "_getAllContacts" ascii //weight: 1
        $x_1_5 = "www.like4like.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgent_AH_2147817460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgent.AH!MTB"
        threat_id = "2147817460"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/system/app/service.apk" ascii //weight: 1
        $x_1_2 = "putApkToSystem" ascii //weight: 1
        $x_1_3 = "delFileIfExist" ascii //weight: 1
        $x_1_4 = "doSthBySu" ascii //weight: 1
        $x_1_5 = "ScreenCaptureActivity" ascii //weight: 1
        $x_1_6 = "InstallThirdApp" ascii //weight: 1
        $x_1_7 = {61 6d 20 73 74 61 72 74 73 65 72 76 69 63 65 [0-21] 2d 6e [0-37] 2f 2e 50 6f 77 65 72 44 65 74 65 63 74 53 65 72 76 69 63 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_AndroidOS_SAgent_D_2147830889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgent.D!MTB"
        threat_id = "2147830889"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "app_db=apks_data" ascii //weight: 1
        $x_1_2 = "sixtix.chainer.radio" ascii //weight: 1
        $x_2_3 = {07 42 1f 02 35 0f 5a 20 8d 24 07 42 1f 02 35 0f 5b 25 8e 24 07 42 1f 02 35 0f 11 02}  //weight: 2, accuracy: High
        $x_2_4 = {54 60 92 25 16 03 00 08 72 40 98 68 20 43 0b 00 16 02 ff ff 31 04 00 02 38 04 03 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SAgent_H_2147839371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgent.H!MTB"
        threat_id = "2147839371"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 aa 00 f0 ?? fd 11 20 ff f7 ?? ?? ?? 4c 00 21 11 22 02 ?? ff f7 ?? ec a8 1c 02 99 04 aa 01 f0 ?? f8 7c 44 80 21 04 aa 02 98 00 f0 ?? fd 24 68 00 21 80 22 20 1c ff f7 ?? ec 22 1c 29 1c 34 1c 12 31 80 23 92 3c 04 a8 ff f7 ?? fe 20 1c ff f7 ?? ec 29 1c 06 1c 92 31 04 a8 32 1c 23 1c ff f7 ?? fe 21 1c 01 22 01 9b 30 1c ff f7 ?? ec 01 98 ff f7 ?? ec 01 98}  //weight: 1, accuracy: Low
        $x_1_2 = {11 20 df f8 ?? a0 ff f7 ?? ec 00 21 11 22 83 46 ff f7 ?? ec b0 1c 59 46 6a 46 01 f0 ?? f8 80 21 6a 46 58 46 00 f0 ?? fd fa 44 da f8 ?? a0 00 21 80 22 50 46 ff f7 ?? ec 52 46 06 f1 ?? 01 80 23 68 46 ff f7 ?? fd 40 46 ff f7 ?? ec 06 f1 ?? 01 43 46 82 46 68 46 52 46 ff f7 ?? fd 41 46 01 22 3b 46 50 46 ff f7 ?? ec 38 46 ff f7 ?? ec 38 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_AndroidOS_SAgent_I_2147841982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgent.I!MTB"
        threat_id = "2147841982"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSHandler1.ashx?t=request&p=" ascii //weight: 1
        $x_1_2 = "GetAllContactNumbers" ascii //weight: 1
        $x_1_3 = "SMSServiceBootReceiver" ascii //weight: 1
        $x_1_4 = "MSG_SNED_TO_CONTACTS" ascii //weight: 1
        $x_1_5 = "SMSSender" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgent_J_2147841983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgent.J!MTB"
        threat_id = "2147841983"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ru/misha/smsbuy" ascii //weight: 1
        $x_1_2 = "is_my_messages" ascii //weight: 1
        $x_1_3 = "TUMBLER_IDS" ascii //weight: 1
        $x_1_4 = "SMSObserver_Balance" ascii //weight: 1
        $x_1_5 = "ValidBalanceSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgent_K_2147843426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgent.K!MTB"
        threat_id = "2147843426"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deleteFoder1" ascii //weight: 1
        $x_1_2 = "updSendSMSStatus" ascii //weight: 1
        $x_1_3 = "bankHijack" ascii //weight: 1
        $x_1_4 = "BANK_TOP_CHECK_TIME" ascii //weight: 1
        $x_1_5 = "sendSMSService" ascii //weight: 1
        $x_1_6 = "uploadPhone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgent_L_2147843427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgent.L!MTB"
        threat_id = "2147843427"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PLATFORM_START_SMS_CHARGE" ascii //weight: 1
        $x_1_2 = "SmsTransmit_%d" ascii //weight: 1
        $x_1_3 = "SMS_BLOCKED_ANALYZE" ascii //weight: 1
        $x_1_4 = "SMS_PREPARE_SEND" ascii //weight: 1
        $x_1_5 = "&counter=1&tkInfo=" ascii //weight: 1
        $x_1_6 = "kgqhks_domain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_SAgent_O_2147849353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgent.O!MTB"
        threat_id = "2147849353"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/sp/shyy/status.jsp" ascii //weight: 1
        $x_1_2 = "DYD_SMS_SEND" ascii //weight: 1
        $x_1_3 = "SendMessService" ascii //weight: 1
        $x_1_4 = "com/dd/launcher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SAgent_N_2147890538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SAgent.N!MTB"
        threat_id = "2147890538"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Telephony_MMSmsOCU" ascii //weight: 1
        $x_1_2 = "CallBack_cmcc_net" ascii //weight: 1
        $x_1_3 = "com/asionsky/smsones" ascii //weight: 1
        $x_1_4 = "SmsApplicationEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

