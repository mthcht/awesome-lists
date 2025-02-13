rule Trojan_MSIL_Fabookie_AMAD_2147892938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fabookie.AMAD!MTB"
        threat_id = "2147892938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 25 18 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 72 ?? 01 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

