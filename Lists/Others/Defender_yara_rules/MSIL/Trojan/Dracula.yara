rule Trojan_MSIL_Dracula_RPX_2147907136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dracula.RPX!MTB"
        threat_id = "2147907136"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dracula"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a2 25 20 01 00 00 00 20 6f 00 00 00 28 0a 00 00 0a a2 25 20 02 00 00 00 20 61 00 00 00 28 0a 00 00 0a a2 25 20 03 00 00 00 20 64 00 00 00 28 0a 00 00 0a a2 25 20 04 00 00 00 20 65 00 00 00 28 0a 00 00 0a a2 25 20 05 00 00 00 20 72 00 00 00 28 0a 00 00 0a a2 25 20 06 00 00 00 20 20 00 00 00 28 0a 00 00 0a a2 25 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

