rule Backdoor_AndroidOS_LucBot_B_2147772783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/LucBot.B!MTB"
        threat_id = "2147772783"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "LucBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DECRYPTED AND DELETED APP FROM PHONE" ascii //weight: 1
        $x_1_2 = ".Lucy" ascii //weight: 1
        $x_1_3 = "/private/add_log.php" ascii //weight: 1
        $x_1_4 = "http/private/reg.php" ascii //weight: 1
        $x_1_5 = "last payment method was declined" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

