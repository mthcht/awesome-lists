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

rule Trojan_Linux_SuspiciousCron_C_2147959960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SuspiciousCron.C"
        threat_id = "2147959960"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SuspiciousCron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "crontab -l" wide //weight: 10
        $x_2_2 = {65 00 63 00 68 00 6f 00 20 00 [0-21] 2a 00 20 00 2a 00 20 00 2a 00 20 00 [0-21] 2f 00 74 00 6d 00 70 00 2f 00}  //weight: 2, accuracy: Low
        $x_2_3 = {65 00 63 00 68 00 6f 00 20 00 [0-21] 2a 00 20 00 2a 00 20 00 2a 00 20 00 [0-21] 2f 00 76 00 61 00 72 00 2f 00 74 00 6d 00 70 00 2f 00}  //weight: 2, accuracy: Low
        $x_2_4 = {65 00 63 00 68 00 6f 00 20 00 [0-21] 2a 00 20 00 2a 00 20 00 2a 00 20 00 [0-21] 2f 00 64 00 65 00 76 00 2f 00 73 00 68 00 6d 00 2f 00}  //weight: 2, accuracy: Low
        $x_10_5 = "| crontab -" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

