rule TrojanSpy_AndroidOS_SmsBot_B_2147754557_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsBot.B!MTB"
        threat_id = "2147754557"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gomon48.ru" ascii //weight: 1
        $x_1_2 = "is_divice_admin_absolute" ascii //weight: 1
        $x_1_3 = "const_id_send_sms" ascii //weight: 1
        $x_1_4 = "content://sms/sent" ascii //weight: 1
        $x_1_5 = "app.six.MainActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

