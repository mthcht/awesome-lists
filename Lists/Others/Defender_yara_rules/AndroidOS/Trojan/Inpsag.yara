rule Trojan_AndroidOS_Inpsag_YA_2147756524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Inpsag.YA!MTB"
        threat_id = "2147756524"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Inpsag"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.FakePage.fin" ascii //weight: 1
        $x_1_2 = "com.adrt.CONNECT" ascii //weight: 1
        $x_1_3 = "com.adrt.BREAKPOINT_HIT" ascii //weight: 1
        $x_1_4 = "com.adrt.LOGCAT_ENTRIES" ascii //weight: 1
        $x_1_5 = "RUhFSEZJVUVJRkVGRFNB" ascii //weight: 1
        $x_1_6 = "SDykO6RAY3jIu8St4" ascii //weight: 1
        $x_1_7 = "accounts/password/reset" ascii //weight: 1
        $x_1_8 = "OAEmYobD90i5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

