rule Trojan_MSIL_Pitit_A_2147678855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Pitit.A"
        threat_id = "2147678855"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pitit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1d 28 1d 00 00 0a 72 ?? 00 00 70 72 ?? 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 0a 28 04 00 00 06 6f 20 00 00 0a 02 7b 06 00 00 04 06 6f 21 00 00 0a de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

