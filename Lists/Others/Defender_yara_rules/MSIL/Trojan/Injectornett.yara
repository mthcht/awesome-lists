rule Trojan_MSIL_Injectornett_PGN_2147943769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Injectornett.PGN!MTB"
        threat_id = "2147943769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injectornett"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6e 00 65 00 77 00 2e 00 65 00 76 00 65 00 6e 00 74 00 61 00 77 00 61 00 72 00 64 00 73 00 72 00 75 00 73 00 73 00 69 00 61 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 70 00 2d 00 69 00 6e 00 63 00 6c 00 75 00 64 00 65 00 73 00 2f 00 [0-31] 2e 00 64 00 61 00 74 00}  //weight: 5, accuracy: Low
        $x_5_2 = {68 74 00 74 00 70 73 3a 2f 2f 77 77 77 2e 6e 65 77 2e 65 76 65 6e 74 61 77 61 72 64 73 72 75 73 73 69 61 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f [0-31] 2e 64 61 74}  //weight: 5, accuracy: Low
        $x_5_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6e 00 65 00 77 00 2e 00 65 00 76 00 65 00 6e 00 74 00 61 00 77 00 61 00 72 00 64 00 73 00 72 00 75 00 73 00 73 00 69 00 61 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 70 00 2d 00 69 00 6e 00 63 00 6c 00 75 00 64 00 65 00 73 00 2f 00 [0-31] 2e 00 76 00 64 00 66 00}  //weight: 5, accuracy: Low
        $x_5_4 = {68 74 00 74 00 70 73 3a 2f 2f 77 77 77 2e 6e 65 77 2e 65 76 65 6e 74 61 77 61 72 64 73 72 75 73 73 69 61 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f [0-31] 2e 76 64 66}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

