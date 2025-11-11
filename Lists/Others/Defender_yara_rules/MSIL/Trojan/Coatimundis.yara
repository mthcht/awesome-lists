rule Trojan_MSIL_Coatimundis_A_2147957165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coatimundis.A"
        threat_id = "2147957165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coatimundis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 56 48 44 2e 64 6c 6c 00 6b 65 72 6e 65 6c 33 32 ?? 6d 73 63 6f 72 6c 69 62 00}  //weight: 1, accuracy: Low
        $x_1_2 = {76 68 64 00 5c 56 48 44 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

