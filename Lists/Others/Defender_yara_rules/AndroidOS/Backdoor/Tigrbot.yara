rule Backdoor_AndroidOS_Tigrbot_A_2147655977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Tigrbot.A"
        threat_id = "2147655977"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Tigrbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendSuccess:" ascii //weight: 1
        $x_1_2 = "ro.telephony.disable-call" ascii //weight: 1
        $x_1_3 = "Device restart successfully." ascii //weight: 1
        $x_1_4 = "voicemail status decoding failed" ascii //weight: 1
        $x_1_5 = "New SIM card number to send SMS number is now." ascii //weight: 1
        $x_1_6 = "retry count is too more..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

