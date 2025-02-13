rule Trojan_PowerShell_Rpdactaele_D_2147729386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Rpdactaele.D"
        threat_id = "2147729386"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Rpdactaele"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6f 00 70 00 79 00 2d 00 69 00 74 00 65 00 6d 00 20 00 [0-48] 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 74 00 6f 00 72 00 65 00 5c 00 66 00 69 00 6c 00 65 00 72 00 65 00 70 00 6f 00 73 00 69 00 74 00 6f 00 72 00 79 00 5c 00 70 00 72 00 6e 00 6d 00 73 00 30 00 30 00 33 00 2e 00 69 00 6e 00 66 00 5f 00 61 00 6d 00 64 00 36 00 34 00 5f 00 [0-32] 5c 00 61 00 6d 00 64 00 36 00 34 00 5c 00 70 00 72 00 69 00 6e 00 74 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {74 00 61 00 72 00 67 00 65 00 74 00 [0-48] 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 74 00 6f 00 72 00 65 00 5c 00 66 00 69 00 6c 00 65 00 72 00 65 00 70 00 6f 00 73 00 69 00 74 00 6f 00 72 00 79 00 5c 00 70 00 72 00 6e 00 6d 00 73 00 30 00 30 00 33 00 2e 00 69 00 6e 00 66 00 5f 00 61 00 6d 00 64 00 36 00 34 00 5f 00 [0-32] 5c 00 61 00 6d 00 64 00 36 00 34 00 5c 00 70 00 72 00 69 00 6e 00 74 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

