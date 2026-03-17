rule Trojan_MSIL_PulsarRAT_ZEG_2147964999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PulsarRAT.ZEG!MTB"
        threat_id = "2147964999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PulsarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 16 13 06 2b 18 08 11 06 8f ?? 00 00 01 25 47 20 88 00 00 00 61 d2 52 11 06 17 58 13 06 11 06 08 8e 69 32 e1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

