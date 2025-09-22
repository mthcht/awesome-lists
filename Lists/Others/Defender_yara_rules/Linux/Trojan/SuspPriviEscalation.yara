rule Trojan_Linux_SuspPriviEscalation_B6_2147952714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SuspPriviEscalation.B6"
        threat_id = "2147952714"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SuspPriviEscalation"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sed -n" wide //weight: 2
        $x_2_2 = "exec /bin/bash" wide //weight: 2
        $x_2_3 = " 1>&0" wide //weight: 2
        $x_2_4 = "/etc/hosts" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

