rule Trojan_PowerShell_FormBook_RPA_2147943610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/FormBook.RPA!MTB"
        threat_id = "2147943610"
        type = "Trojan"
        platform = "PowerShell: "
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 25 00 74 00 6d 00 70 00 25 00 5c 00 [0-16] 2e 00 69 00 6e 00 69 00 2c 00 69 00 65 00 78 00}  //weight: 100, accuracy: Low
        $x_100_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 25 00 74 00 6d 00 70 00 25 00 5c 00 [0-16] 2e 00 6c 00 6f 00 67 00 2c 00 69 00 65 00 78 00}  //weight: 100, accuracy: Low
        $x_100_3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 25 00 74 00 6d 00 70 00 25 00 5c 00 [0-16] 2e 00 70 00 64 00 66 00 2c 00 69 00 65 00 78 00}  //weight: 100, accuracy: Low
        $x_1_4 = "a\\x12\\x0cc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

