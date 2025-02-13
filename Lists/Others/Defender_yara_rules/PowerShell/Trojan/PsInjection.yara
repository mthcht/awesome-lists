rule Trojan_PowerShell_PsInjection_A_2147725503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/PsInjection.A"
        threat_id = "2147725503"
        type = "Trojan"
        platform = "PowerShell: "
        family = "PsInjection"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 70 00 65 00 62 00 79 00 74 00 65 00 73 00 20 00 [0-21] 20 00 2d 00 66 00 75 00 6e 00 63 00 72 00 65 00 74 00 75 00 72 00 6e 00 74 00 79 00 70 00 65 00 20 00 77 00 73 00 74 00 72 00 69 00 6e 00 67 00 20 00 2d 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 70 00 65 00 62 00 79 00 74 00 65 00 73 00 20 00 [0-21] 20 00 2d 00 70 00 72 00 6f 00 63 00 6e 00 61 00 6d 00 65 00 20 00 [0-21] 20 00 2d 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00 20 00 74 00 61 00 72 00 67 00 65 00 74 00 2e 00 6c 00 6f 00 63 00 61 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Invoke-ReflectivePEInjection" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

