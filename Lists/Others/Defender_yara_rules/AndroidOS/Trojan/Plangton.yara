rule Trojan_AndroidOS_Plangton_A_2147808535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Plangton.A"
        threat_id = "2147808535"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Plangton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/commandstatus" ascii //weight: 1
        $x_1_2 = "com.apperhand.global" ascii //weight: 1
        $x_1_3 = "M_SERVER_URL" ascii //weight: 1
        $x_1_4 = "was activated, SABABA!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Plangton_RT_2147919998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Plangton.RT"
        threat_id = "2147919998"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Plangton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Apperhand service was started successfully" ascii //weight: 1
        $x_1_2 = "CRoQAlVGS1keGVoEHgRLEBoOGRdLEUE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

