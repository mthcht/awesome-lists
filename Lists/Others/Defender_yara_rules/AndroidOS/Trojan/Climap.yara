rule Trojan_AndroidOS_Climap_A_2147831398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Climap.A!MTB"
        threat_id = "2147831398"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Climap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PhotoTaker" ascii //weight: 1
        $x_1_2 = "SMSLister" ascii //weight: 1
        $x_1_3 = "DirLister" ascii //weight: 1
        $x_1_4 = "visitAllDirsAndFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

