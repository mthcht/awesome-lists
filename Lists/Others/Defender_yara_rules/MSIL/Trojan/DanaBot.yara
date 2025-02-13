rule Trojan_MSIL_DanaBot_PTAD_2147894583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DanaBot.PTAD!MTB"
        threat_id = "2147894583"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 28 54 00 00 0a 74 11 00 00 01 13 05 73 55 00 00 0a 13 06 16 0b 2b 21 11 05 07 16 6f 56 00 00 0a 13 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

