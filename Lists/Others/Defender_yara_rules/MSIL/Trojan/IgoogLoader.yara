rule Trojan_MSIL_IgoogLoader_SPQ_2147846383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/IgoogLoader.SPQ!MTB"
        threat_id = "2147846383"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IgoogLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 18 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 72 68 1d 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 0b 07 7e 18 00 00 04 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

