rule Trojan_Linux_GitCredentials_A_2147793581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/GitCredentials.A"
        threat_id = "2147793581"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "GitCredentials"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 67 00 69 00 74 00 20 (00 67 00 72 00 65|00 6c 00 6f 00 67 00 20 00 2d) 00 20}  //weight: 10, accuracy: Low
        $x_1_2 = "password" wide //weight: 1
        $x_1_3 = "pass" wide //weight: 1
        $x_1_4 = "pw" wide //weight: 1
        $x_1_5 = "key" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

