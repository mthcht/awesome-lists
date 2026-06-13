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

