rule Backdoor_AndroidOS_BeanBot_A_2147811432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/BeanBot.A!xp"
        threat_id = "2147811432"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "BeanBot"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "data/data/com.iPhand.FirstAid/databases" ascii //weight: 1
        $x_1_2 = "com.and.sms.send" ascii //weight: 1
        $x_1_3 = "com.and.sms.delivery" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

