rule Trojan_AndroidOS_SendSMS_A_2147784806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SendSMS.A!MTB"
        threat_id = "2147784806"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SendSMS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setSMSValURL" ascii //weight: 1
        $x_1_2 = "confirm_send_sms_msg" ascii //weight: 1
        $x_1_3 = "Please enter both phone number and message" ascii //weight: 1
        $x_1_4 = "Shortcut2ApkActivity" ascii //weight: 1
        $x_1_5 = "sms_service/boibaitay/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SendSMS_B_2147784808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SendSMS.B!MTB"
        threat_id = "2147784808"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SendSMS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sent_sms_count" ascii //weight: 1
        $x_1_2 = "url_config_auto_sms" ascii //weight: 1
        $x_1_3 = {4c 63 6f 6d 2f 68 64 63 [0-20] 53 65 6e 64 53 4d 53}  //weight: 1, accuracy: Low
        $x_1_4 = "getPayedLink" ascii //weight: 1
        $x_1_5 = "activate.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SendSMS_C_2147788225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SendSMS.C!MTB"
        threat_id = "2147788225"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SendSMS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "maxSms" ascii //weight: 1
        $x_1_2 = "start sms: mode =" ascii //weight: 1
        $x_1_3 = "maxCost" ascii //weight: 1
        $x_1_4 = "blockPhones" ascii //weight: 1
        $x_1_5 = "smsTimeout" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SendSMS_D_2147788227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SendSMS.D!MTB"
        threat_id = "2147788227"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SendSMS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "antiIcon" ascii //weight: 1
        $x_1_2 = "custom.sms." ascii //weight: 1
        $x_1_3 = "antiUninstall" ascii //weight: 1
        $x_1_4 = "startSmsTimer" ascii //weight: 1
        $x_1_5 = "ru.uninstall.FakeActivity" ascii //weight: 1
        $x_1_6 = "start sms: mode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

