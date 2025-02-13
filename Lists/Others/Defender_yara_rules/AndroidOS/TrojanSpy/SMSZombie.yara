rule TrojanSpy_AndroidOS_SMSZombie_B_2147786558_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSZombie.B!xp"
        threat_id = "2147786558"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSZombie"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ACTIOIN_SEND_SMS_BUY" ascii //weight: 1
        $x_1_2 = "SEND_SMS_NUM" ascii //weight: 1
        $x_1_3 = "libkjOnlinePay.so" ascii //weight: 1
        $x_1_4 = "/wmapp/WMAppInit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

