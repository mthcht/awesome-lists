rule Trojan_MacOS_ORat_A_2147820290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/ORat.A"
        threat_id = "2147820290"
        type = "Trojan"
        platform = "MacOS: "
        family = "ORat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "orat/utils" ascii //weight: 1
        $x_1_2 = "orat/endpoint" ascii //weight: 1
        $x_1_3 = "orat/cmd/agent/app/ssh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

