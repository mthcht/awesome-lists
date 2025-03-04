rule Trojan_AndroidOS_Zanubis_B_2147831546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Zanubis.B"
        threat_id = "2147831546"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Zanubis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "datos_iniciales_cliente" ascii //weight: 1
        $x_1_2 = "rev_permiso_sms" ascii //weight: 1
        $x_1_3 = "tagets_find" ascii //weight: 1
        $x_1_4 = "sock_est" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

