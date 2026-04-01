rule Trojan_MacOS_SuspFileDownload_SA_2147966058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspFileDownload.SA"
        threat_id = "2147966058"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspFileDownload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 75 00 72 00 6c 00 20 00 2d 00 6f 00 20 00 2f 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00 43 00 61 00 63 00 68 00 65 00 73 00 2f 00 63 00 6f 00 6d 00 2e 00 61 00 70 00 70 00 6c 00 65 00 2e 00 [0-48] 20 00 2d 00 64 00 20 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 73 00 2e 00 6e 00 70 00 6d 00 2e 00 6f 00 72 00 67 00 2f 00 [0-48] 2d 00 73 00 20 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {63 00 68 00 6d 00 6f 00 64 00 20 00 37 00 37 00 30 00 20 00 2f 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00 43 00 61 00 63 00 68 00 65 00 73 00 2f 00 63 00 6f 00 6d 00 2e 00 61 00 70 00 70 00 6c 00 65 00 2e 00 [0-48] 20 00 26 00 26 00 20 00 [0-16] 73 00 68 00 20 00 2d 00 63 00 [0-5] 2f 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 2f 00 43 00 61 00 63 00 68 00 65 00 73 00 2f 00 63 00 6f 00 6d 00 2e 00 61 00 70 00 70 00 6c 00 65 00 2e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

