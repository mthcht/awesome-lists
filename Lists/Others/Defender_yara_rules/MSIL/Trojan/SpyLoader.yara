rule Trojan_MSIL_SpyLoader_NL_2147896152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyLoader.NL!MTB"
        threat_id = "2147896152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 16 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 0a 16 0b 2b 13 02 07 06 07 06 8e 69 5d 91 02 07 91 61 d2 9c 07 17 58 0b 07 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

