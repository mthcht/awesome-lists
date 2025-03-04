rule Trojan_AndroidOS_SMSBot_A_2147788230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSBot.A!MTB"
        threat_id = "2147788230"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "saved_auth_sms_text" ascii //weight: 1
        $x_1_2 = "SmsLog" ascii //weight: 1
        $x_1_3 = "BOT_ID" ascii //weight: 1
        $x_1_4 = "/bot.php" ascii //weight: 1
        $x_1_5 = "saved_sms_number" ascii //weight: 1
        $x_1_6 = "BotService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

