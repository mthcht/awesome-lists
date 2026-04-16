rule Trojan_Linux_CertipyAuth_AM_2147967144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CertipyAuth.AM"
        threat_id = "2147967144"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CertipyAuth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certipy" wide //weight: 1
        $x_1_2 = " auth " wide //weight: 1
        $x_1_3 = "-pfx " wide //weight: 1
        $n_1_4 = "11999e4c-5873-4373-bd82-7bb45143b3a5" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

