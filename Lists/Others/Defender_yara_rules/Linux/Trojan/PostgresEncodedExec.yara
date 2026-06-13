rule Trojan_Linux_PostgresEncodedExec_A_2147971531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/PostgresEncodedExec.A"
        threat_id = "2147971531"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "PostgresEncodedExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sh -c " wide //weight: 1
        $x_10_2 = "echo " wide //weight: 10
        $x_10_3 = {62 00 61 00 73 00 65 00 36 00 34 00 20 00 2d 00 64 00 27 ff ff 00 7c 00 27 ff ff 00 2b 02 02 00 73 00 68 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

