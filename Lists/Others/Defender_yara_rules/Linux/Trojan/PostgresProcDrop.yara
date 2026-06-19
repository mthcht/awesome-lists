rule Trojan_Linux_PostgresProcDrop_A_2147971530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/PostgresProcDrop.A"
        threat_id = "2147971530"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "PostgresProcDrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sh -c " wide //weight: 1
        $x_10_2 = {63 00 70 00 20 00 2f 00 70 00 72 00 6f 00 63 00 2f 00 23 07 07 03 30 2d 39 2f 00 65 00 78 00 65 00 20 00}  //weight: 10, accuracy: Low
        $x_10_3 = {26 00 26 00 27 ff ff 00 63 00 68 00 6d 00 6f 00 64 00 20 00 2b 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_PostgresProcDrop_B_2147971929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/PostgresProcDrop.B"
        threat_id = "2147971929"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "PostgresProcDrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sh -c " wide //weight: 1
        $x_10_2 = "wget " wide //weight: 10
        $x_10_3 = "curl " wide //weight: 10
        $x_10_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00}  //weight: 10, accuracy: Low
        $x_10_5 = {63 00 68 00 6d 00 6f 00 64 00 20 00 29 05 05 00 20 00}  //weight: 10, accuracy: Low
        $x_10_6 = "chmod +x " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

