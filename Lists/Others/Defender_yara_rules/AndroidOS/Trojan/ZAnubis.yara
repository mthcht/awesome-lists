rule Trojan_AndroidOS_ZAnubis_M_2147850576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/ZAnubis.M"
        threat_id = "2147850576"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "ZAnubis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "servicio/IntSrvRequest" ascii //weight: 2
        $x_2_2 = "SrvToastAccesibilidad" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

