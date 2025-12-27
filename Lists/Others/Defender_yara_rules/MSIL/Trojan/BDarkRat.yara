rule Trojan_MSIL_BDarkRat_ABR_2147958213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BDarkRat.ABR!MTB"
        threat_id = "2147958213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BDarkRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 16 02 06 8f ?? 00 00 01 25 47 7e ?? 00 00 04 d2 61 d2 52 06 17 58 0a 06 02 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

