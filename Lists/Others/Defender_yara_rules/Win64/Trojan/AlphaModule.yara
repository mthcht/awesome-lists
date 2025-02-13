rule Trojan_Win64_AlphaModule_A_2147849110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AlphaModule.A"
        threat_id = "2147849110"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AlphaModule"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 74 43 72 65 61 74 65 53 65 63 74 69 6f 6e 20 2d 20 46 61 69 6c 00 00 70 4e 74 4d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 20 2d 20 46 61 69 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

