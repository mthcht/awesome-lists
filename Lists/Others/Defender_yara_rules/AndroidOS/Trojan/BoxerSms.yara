rule Trojan_AndroidOS_BoxerSms_A_2147652257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BoxerSms.A"
        threat_id = "2147652257"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BoxerSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ReadOffertActivity.java" ascii //weight: 1
        $x_1_2 = "Fuuuuu!!" ascii //weight: 1
        $x_1_3 = "Error reading sms.cfg" ascii //weight: 1
        $x_1_4 = "depositmobi" ascii //weight: 1
        $x_1_5 = "sendedSmsCounter" ascii //weight: 1
        $x_1_6 = "i_disagree_offert" ascii //weight: 1
        $x_1_7 = "i_accept_offert" ascii //weight: 1
        $x_1_8 = "read_offert_button" ascii //weight: 1
        $x_1_9 = "needSendedToActivate" ascii //weight: 1
        $x_1_10 = "main_offert_text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_BoxerSms_B_2147668092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BoxerSms.B"
        threat_id = "2147668092"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BoxerSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isSMSLimitEnabled" ascii //weight: 1
        $x_1_2 = "megafonRules" ascii //weight: 1
        $x_1_3 = "getRulesTexts" ascii //weight: 1
        $x_1_4 = "OpInfo.java" ascii //weight: 1
        $x_1_5 = "authSuccess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_BoxerSms_C_2147668093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BoxerSms.C"
        threat_id = "2147668093"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BoxerSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GrantAccess.java" ascii //weight: 1
        $x_1_2 = "BEEELINE_ID" ascii //weight: 1
        $x_1_3 = "LINK_THAT_WAS_DONE" ascii //weight: 1
        $x_1_4 = "OFFERT_ACTIVITY" ascii //weight: 1
        $x_1_5 = "full_offerts_text" ascii //weight: 1
        $x_1_6 = "i_disagree_offert" ascii //weight: 1
        $x_1_7 = "i_accept_offert" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_BoxerSms_D_2147668094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BoxerSms.D"
        threat_id = "2147668094"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BoxerSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "OffertActivity.java" ascii //weight: 1
        $x_1_2 = "Scheduling registration retry, backoff =" ascii //weight: 1
        $x_1_3 = "PAYED_YES" ascii //weight: 1
        $x_1_4 = "SENDED_SMS_COUNTER_KEY" ascii //weight: 1
        $x_1_5 = "KY_ID" ascii //weight: 1
        $x_1_6 = {73 6d 73 51 75 61 6e 74 69 74 79 [0-5] 73 6d 73 54 65 78 74 [0-5] 73 6d 73 5f 74 65 78 74 [0-5] 73 74 61 72 74 [0-5] 73 74 61 72 74 41 63 74 69 76 69 74 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

