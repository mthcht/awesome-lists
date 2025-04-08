rule Trojan_Linux_SuspiciousCron_A_2147938121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SuspiciousCron.A"
        threat_id = "2147938121"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SuspiciousCron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "crontab -l" wide //weight: 2
        $x_2_2 = "echo */1 * * * * " wide //weight: 2
        $x_2_3 = "crontab -" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

