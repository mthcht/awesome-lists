rule Trojan_PowerShell_Wurshel_A_2147726249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Wurshel.A"
        threat_id = "2147726249"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Wurshel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".DownloadFile('http://zxciuniqhweizsds.com/" wide //weight: 1
        $x_1_2 = {2e 00 63 00 6c 00 61 00 73 00 73 00 27 00 2c 00 20 00 24 00 65 00 6e 00 76 00 3a 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 20 00 2b 00 20 00 27 00 5c 00 5c 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00 27 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

