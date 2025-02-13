rule Trojan_AndroidOS_Shedun_A_2147901923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Shedun.A"
        threat_id = "2147901923"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Shedun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "decodeDexAndReplace" ascii //weight: 1
        $x_1_2 = "20230610HelloDog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

