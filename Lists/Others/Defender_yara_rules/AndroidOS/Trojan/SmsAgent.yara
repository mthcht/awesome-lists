rule Trojan_AndroidOS_SmsAgent_C_2147787850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.C"
        threat_id = "2147787850"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYSMSPayer" ascii //weight: 1
        $x_1_2 = "SMSSendStateReceiver" ascii //weight: 1
        $x_1_3 = "pay_is_server_record" ascii //weight: 1
        $x_1_4 = "isCreatedShorcut" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsAgent_D_2147787851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.D"
        threat_id = "2147787851"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MoblieAgent_sys_config" ascii //weight: 1
        $x_1_2 = "_pay_logaction" ascii //weight: 1
        $x_1_3 = "USER_STATUS_LOGIN" ascii //weight: 1
        $x_1_4 = "getDefaultDataPhoneId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsAgent_G_2147851356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.G"
        threat_id = "2147851356"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sys_message_address" ascii //weight: 2
        $x_2_2 = "sys_send_contents" ascii //weight: 2
        $x_2_3 = "sys_make_web_quick" ascii //weight: 2
        $x_2_4 = "TnkLibAccess" ascii //weight: 2
        $x_2_5 = "affmob.tornika.com/service_lib.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_SmsAgent_AF_2147892072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.AF"
        threat_id = "2147892072"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "stacks_sms_daily_cap" ascii //weight: 2
        $x_2_2 = "SMS_SENT_START_TAG" ascii //weight: 2
        $x_2_3 = "stacks_sms_tick_time_end" ascii //weight: 2
        $x_2_4 = "sms_amount_send" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsAgent_B_2147895641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.B"
        threat_id = "2147895641"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CodeFromPanel" ascii //weight: 2
        $x_2_2 = "/89.23.98.16/send_data" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsAgent_Q_2147908490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.Q"
        threat_id = "2147908490"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "lotuseed_jr_ok" ascii //weight: 2
        $x_2_2 = "lotuseed_update_jr" ascii //weight: 2
        $x_2_3 = "lotuseed_jr_already_latest" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsAgent_AP_2147909154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.AP"
        threat_id = "2147909154"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "example/appjava/ReceiveSms" ascii //weight: 3
        $x_1_2 = "&text=*New SMS Ngan Laju* %0A%0A*Sender * : _" ascii //weight: 1
        $x_1_3 = "_%0A%0A*Type Perangkat : *" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SmsAgent_AW_2147911363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.AW"
        threat_id = "2147911363"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ForwardTaskForTelegram" ascii //weight: 2
        $x_2_2 = "forwardViaSMS" ascii //weight: 2
        $x_2_3 = "COURIERADFYFESG7VIFXADMIN10/reciever.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsAgent_AX_2147911609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.AX"
        threat_id = "2147911609"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "calendar/SMSMonitor" ascii //weight: 2
        $x_2_2 = "getSlotBySubscription" ascii //weight: 2
        $x_2_3 = "calendar/SendIntro" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsAgent_NM_2147912796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.NM"
        threat_id = "2147912796"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KEY_CHECK_SEND_KEYWORK" ascii //weight: 2
        $x_2_2 = "catch_confirmSms" ascii //weight: 2
        $x_2_3 = "SHOW_START_SMS_SEVICE" ascii //weight: 2
        $x_2_4 = "settingPerSms" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsAgent_M_2147916235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.M"
        threat_id = "2147916235"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SHOW_START_SMS_SEVICE" ascii //weight: 2
        $x_2_2 = "SEND_HELLOSAY_CATCH" ascii //weight: 2
        $x_2_3 = "SAVE_PER_INIT_SYSTEM" ascii //weight: 2
        $x_2_4 = "showDialogNotifiSendSMS" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_SmsAgent_AH_2147916912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.AH"
        threat_id = "2147916912"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KEY_TEST_TOTAL_CONVERSATION" ascii //weight: 2
        $x_2_2 = "/productinfo/already_send" ascii //weight: 2
        $x_2_3 = "ACTION_MESSAGE_SEND_ALREADY" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsAgent_AZ_2147919944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.AZ"
        threat_id = "2147919944"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "poland_xxx17/FailedActivity" ascii //weight: 2
        $x_2_2 = "poland_xxx17/RulesActivity" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsAgent_AN_2147936552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsAgent.AN"
        threat_id = "2147936552"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "executor/TotalReceiver" ascii //weight: 2
        $x_2_2 = "executor_receiver_method" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

