rule Trojan_MSIL_BlackShades_ABS_2147971443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BlackShades.ABS!MTB"
        threat_id = "2147971443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackShades"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 12 02 09 20 f8 00 00 00 58 11 11 1f 28 5a 58 11 12 16 1f 28 28 ?? 00 00 0a 11 12 1a 94 17 59 17 58 8d ?? 00 00 01 13 13 02 11 12 1b 94 11 13 16 11 13 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

