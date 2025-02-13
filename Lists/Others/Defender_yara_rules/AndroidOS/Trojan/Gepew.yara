rule Trojan_AndroidOS_Gepew_A_2147918412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gepew.A"
        threat_id = "2147918412"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gepew"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/kbs.php?m=Api&a=" ascii //weight: 2
        $x_2_2 = "Contact&status=1&imsi=" ascii //weight: 2
        $x_2_3 = "SMSSendComplate&to=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

