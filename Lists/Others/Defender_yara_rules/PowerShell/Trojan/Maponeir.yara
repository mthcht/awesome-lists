rule Trojan_PowerShell_Maponeir_A_2147725693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Maponeir.A"
        threat_id = "2147725693"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Maponeir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 28 00 27 [0-4] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 64 00 6c 00 2e 00 64 00 72 00 6f 00 70 00 62 00 6f 00 78 00 75 00 73 00 65 00 72 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 28 00 27 [0-4] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 64 00 72 00 69 00 76 00 65 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 6f 00 70 00 65 00 6e 00 3f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {28 00 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 2b 00 27 5c 00 69 00 6e 00 69 00 74 00 2e 00 70 00 73 00 31 00 27 29 00 [0-16] 3b 00 28 00 6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

