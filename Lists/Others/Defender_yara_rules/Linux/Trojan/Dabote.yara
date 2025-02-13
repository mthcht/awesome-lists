rule Trojan_Linux_Dabote_A_2147770027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Dabote.A"
        threat_id = "2147770027"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Dabote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dynddns.cf/start/help/start -O start" ascii //weight: 1
        $x_1_2 = "chmod 777 /etc/init.d/startpstart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

