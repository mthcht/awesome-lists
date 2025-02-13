rule Trojan_AndroidOS_VolterSms_A_2147655548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/VolterSms.A"
        threat_id = "2147655548"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "VolterSms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AlterSMSActivity.java" ascii //weight: 1
        $x_1_2 = "/api/get_oss/" ascii //weight: 1
        $x_1_3 = "SMS_DELIVERED" ascii //weight: 1
        $x_1_4 = {4c 63 6f 6d 2f (61 6c 74|76 6f 6c) 2f 73 6d 73 2f 52 24 73 74 72 69 6e 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

