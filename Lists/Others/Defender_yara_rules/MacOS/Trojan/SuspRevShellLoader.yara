rule Trojan_MacOS_SuspRevShellLoader_A_2147946208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspRevShellLoader.A"
        threat_id = "2147946208"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspRevShellLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 2f 00 62 00 75 00 72 00 70 00 20 00 73 00 75 00 69 00 74 00 65 00 20 00 63 00 6f 00 6d 00 6d 00 75 00 6e 00 69 00 74 00 79 00 20 00 65 00 64 00 69 00 74 00 69 00 6f 00 6e 00 2e 00 61 00 70 00 70 00 2f 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 73 00 2f 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 6a 00 72 00 65 00 2e 00 62 00 75 00 6e 00 64 00 6c 00 65 00 2f 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 73 00 2f 00 68 00 6f 00 6d 00 65 00 2f 00 62 00 69 00 6e 00 2f 00 6a 00 61 00 76 00 61 00 [0-6] 2d 00 6a 00 61 00 72 00}  //weight: 2, accuracy: Low
        $x_1_2 = {2e 00 2f 00 72 00 65 00 76 00 65 00 72 00 73 00 65 00 5f 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 6a 00 61 00 72 00 [0-64] 20 00 34 00 34 00 34 00 33 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 2f 00 72 00 65 00 76 00 65 00 72 00 73 00 65 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 6a 00 61 00 72 00 [0-64] 20 00 34 00 34 00 34 00 33 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

