rule Trojan_MSIL_IceXLoader_NEAA_2147836090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/IceXLoader.NEAA!MTB"
        threat_id = "2147836090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IceXLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 01 00 00 0a 25 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 2b 6f ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
        $x_2_2 = "www.filifilm.com.br" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

