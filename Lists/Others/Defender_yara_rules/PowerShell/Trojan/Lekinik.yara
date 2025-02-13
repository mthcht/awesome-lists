rule Trojan_PowerShell_Lekinik_A_2147752735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Lekinik.A"
        threat_id = "2147752735"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Lekinik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-8] 2d 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 74 00 79 00 6c 00 65 00 [0-8] 68 00 69 00 64 00 64 00 65 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {69 00 65 00 78 00 [0-10] 67 00 65 00 74 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 [0-12] 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 [0-240] 2e 00 70 00 73 00 [0-12] 72 00 65 00 70 00 6c 00 61 00 63 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

