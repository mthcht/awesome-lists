rule Trojan_AndroidOS_Pigetrl_HT_2147927147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Pigetrl.HT"
        threat_id = "2147927147"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Pigetrl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.lololo.MainActivity" ascii //weight: 1
        $x_1_2 = "LockService$100000000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

