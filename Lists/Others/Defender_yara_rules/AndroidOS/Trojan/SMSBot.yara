rule Trojan_AndroidOS_SmsBot_A_2147754218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsBot.A"
        threat_id = "2147754218"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RemoveAllSmsAnswers" ascii //weight: 1
        $x_1_2 = "startBackgroundSms()" ascii //weight: 1
        $x_1_3 = "Ldelete/off/AdminReceiver;" ascii //weight: 1
        $x_1_4 = "SIPMLE_PHONE_AND_TEXT" ascii //weight: 1
        $x_1_5 = "isFisrt(): true" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsBot_A_2147754218_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsBot.A"
        threat_id = "2147754218"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "** Service (fullsms_" ascii //weight: 1
        $x_1_2 = "** Service (install_" ascii //weight: 1
        $x_1_3 = "** Service (sms_" ascii //weight: 1
        $x_10_4 = {0c 02 23 73 [0-4] e2 04 00 18 8d 44 4f 04 03 01 e2 04 00 10 8d 44 4f 04 03 06 e2 04 00 08 8d 44 4f 04 03 08 8d 00 4f 00 03 09 4d 03 02 09 01 12 35 72 2f 00 01 10 54 a3 [0-4] 21 33 35 30 1e 00 54 a3 [0-4] 48 04 03 00 71 00 [0-4] 00 00 0c 05 46 05 05 02 71 00 [0-4] 00 00 0c 06 46 06 06 02 21 66 94 06 00 06 48 05 05 06 b7 54 8d 44 4f 04 03 00 d8 00 00 01 28 e0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

