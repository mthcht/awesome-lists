rule Trojan_PowerShell_Powessere_H_2147729398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Powessere.H"
        threat_id = "2147729398"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 6a 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 76 00 61 00 6c 00 5d 00 3a 00 3a 00 6a 00 73 00 63 00 72 00 69 00 70 00 74 00 65 00 76 00 61 00 6c 00 75 00 61 00 74 00 65 00 28 00 [0-2] 67 00 65 00 74 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00 [0-2] 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 76 00 69 00 73 00 75 00 61 00 6c 00 62 00 61 00 73 00 69 00 63 00 2e 00 69 00 6e 00 74 00 65 00 72 00 61 00 63 00 74 00 69 00 6f 00 6e 00 5d 00 3a 00 3a 00 67 00 65 00 74 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00 [0-2] 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

