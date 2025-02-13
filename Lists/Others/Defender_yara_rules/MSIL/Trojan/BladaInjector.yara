rule Trojan_MSIL_BladaInjector_2147743188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BladaInjector!MTB"
        threat_id = "2147743188"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BladaInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 0b 16 0c 10 00 73 ?? 00 00 0a 0a 06 0b 16 0c 07 12 02 28 ?? 01 00 0a 06 20 10 27 00 00 28 ?? 01 00 0a 26 de}  //weight: 1, accuracy: Low
        $x_1_2 = {25 47 03 06 03 10 00 02 06 8f ?? 00 00 01 25 47 03 06 03 8e 69 5d 91 06 04 03 8e 69 5d 58 04 5f 61 d2 61 d2 52}  //weight: 1, accuracy: Low
        $x_1_3 = {61 03 61 0a 10 00 02 20 ?? ?? ?? ?? 61 03 61 0a 7e 03 00 00 04 0c 08 74 ?? 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b 17 13 0e 38 7d ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

