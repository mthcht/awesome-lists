rule Trojan_AndroidOS_Smsfactory_AA_2147824877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsfactory.AA"
        threat_id = "2147824877"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsfactory"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$this$hideAppIcon" ascii //weight: 1
        $x_1_2 = "EndlessService::lock" ascii //weight: 1
        $x_1_3 = "$this$getInstallDate" ascii //weight: 1
        $x_1_4 = "SmsSentReceiverProxy" ascii //weight: 1
        $x_1_5 = "$this$isCallStateIdle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsfactory_AB_2147824878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsfactory.AB"
        threat_id = "2147824878"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsfactory"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FIRST_OS_PUSH_HAPPENED" ascii //weight: 1
        $x_1_2 = "stacks_sms_tick_time_end" ascii //weight: 1
        $x_1_3 = "SMS_SENT_CAP_TAG" ascii //weight: 1
        $x_1_4 = "sms_amount_send" ascii //weight: 1
        $x_1_5 = "getStacksSMSServer" ascii //weight: 1
        $x_1_6 = "isSMSSentLimitReached" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsfactory_AC_2147824879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsfactory.AC"
        threat_id = "2147824879"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsfactory"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "menus_step" ascii //weight: 1
        $x_1_2 = "app_db=apks_data" ascii //weight: 1
        $x_1_3 = "devices_question" ascii //weight: 1
        $x_1_4 = "programmed_job" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

