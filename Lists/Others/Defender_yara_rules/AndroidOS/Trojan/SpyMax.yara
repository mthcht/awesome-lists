rule Trojan_AndroidOS_SpyMax_A_2147817729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyMax.A"
        threat_id = "2147817729"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyMax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tttrqefvqrevagyqztwwzyq4159" ascii //weight: 1
        $x_1_2 = "xwmgcej4161" ascii //weight: 1
        $x_1_3 = "QdTRIWUx4157" ascii //weight: 1
        $x_1_4 = "ahbzvqbfu4158" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

