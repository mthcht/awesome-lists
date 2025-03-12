rule Trojan_PowerShell_Timestomp_A_2147777453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Timestomp.A"
        threat_id = "2147777453"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Timestomp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 00 47 00 65 00 74 00 2d 00 49 00 74 00 65 00 6d 00 20 00 [0-160] 29 00 2e 00 43 00 72 00 65 00 61 00 74 00 69 00 6f 00 6e 00 54 00 69 00 6d 00 65 00 20 00 3d 00 20 00 28 00 47 00 65 00 74 00 2d 00 49 00 74 00 65 00 6d 00 20 00 [0-160] 29 00 2e 00 43 00 72 00 65 00 61 00 74 00 69 00 6f 00 6e 00 54 00 69 00 6d 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {28 00 47 00 65 00 74 00 2d 00 49 00 74 00 65 00 6d 00 20 00 [0-160] 29 00 2e 00 4c 00 61 00 73 00 74 00 41 00 63 00 63 00 65 00 73 00 73 00 54 00 69 00 6d 00 65 00 20 00 3d 00 20 00 28 00 47 00 65 00 74 00 2d 00 49 00 74 00 65 00 6d 00 20 00 [0-160] 29 00 2e 00 4c 00 61 00 73 00 74 00 41 00 63 00 63 00 65 00 73 00 73 00 54 00 69 00 6d 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {28 00 47 00 65 00 74 00 2d 00 49 00 74 00 65 00 6d 00 20 00 [0-160] 29 00 2e 00 4c 00 61 00 73 00 74 00 57 00 72 00 69 00 74 00 65 00 54 00 69 00 6d 00 65 00 20 00 3d 00 20 00 28 00 47 00 65 00 74 00 2d 00 49 00 74 00 65 00 6d 00 20 00 [0-160] 29 00 2e 00 4c 00 61 00 73 00 74 00 57 00 72 00 69 00 74 00 65 00 54 00 69 00 6d 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_PowerShell_Timestomp_B_2147935847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Timestomp.B"
        threat_id = "2147935847"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Timestomp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 [0-6] 28 00 67 00 65 00 74 00 2d 00 63 00 68 00 69 00 6c 00 64 00 69 00 74 00 65 00 6d 00}  //weight: 10, accuracy: Low
        $x_10_2 = {29 00 2e 00 63 00 72 00 65 00 61 00 74 00 69 00 6f 00 6e 00 74 00 69 00 6d 00 65 00 [0-6] 3d 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

