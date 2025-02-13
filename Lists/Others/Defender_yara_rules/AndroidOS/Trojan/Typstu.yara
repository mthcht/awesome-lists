rule Trojan_AndroidOS_Typstu_A_2147853377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Typstu.A"
        threat_id = "2147853377"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Typstu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e2c4x2a4a4u2" ascii //weight: 1
        $x_1_2 = "com.and.snd.FlashlightLEDService" ascii //weight: 1
        $x_1_3 = "mt/w264y234c4z2y2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

