rule Trojan_Linux_SuspMasquerade_TV5_2147966216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SuspMasquerade.TV5"
        threat_id = "2147966216"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SuspMasquerade"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl " wide //weight: 1
        $x_1_2 = "wget " wide //weight: 1
        $x_1_3 = "tpcp.tar.gz" wide //weight: 1
        $x_10_4 = "scan.aquasecurtiy.org" wide //weight: 10
        $n_100_5 = "application/json" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

