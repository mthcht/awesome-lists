rule Trojan_AndroidOS_Mirai_A_2147899819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mirai.A"
        threat_id = "2147899819"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.global.latinotvod" ascii //weight: 1
        $x_1_2 = "com.ijm.dataencryption.DETool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

