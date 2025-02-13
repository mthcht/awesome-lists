rule Trojan_MSIL_lokiBot_CW_2147841267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/lokiBot.CW!MTB"
        threat_id = "2147841267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "lokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {03 04 08 5d 91 07 04 1f 16 5d 91 61 28 f4 00 00 0a 03 04 17 58 08 5d 91 28 f5 00 00 0a 59 06 58 06 5d d2 0d}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

