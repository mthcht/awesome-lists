rule Trojan_Linux_CertipyReq_AM_2147967143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CertipyReq.AM"
        threat_id = "2147967143"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CertipyReq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certipy" wide //weight: 1
        $x_1_2 = " req " wide //weight: 1
        $x_1_3 = "-template " wide //weight: 1
        $x_1_4 = "-upn " wide //weight: 1
        $n_1_5 = "0524355c-515b-4dca-9488-dafedbad05d4" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

