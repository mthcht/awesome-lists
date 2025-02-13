rule Trojan_MSIL_Discoste_RS_2147833672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Discoste.RS!MTB"
        threat_id = "2147833672"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Discoste"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 02 07 18 6f 0f 00 00 0a 0c 06 08 1f 10 28 10 00 00 0a 6f 11 00 00 0a 26 00 07 18 58 0b 07 02 6f 0c 00 00 0a fe 04 13 04 11 04 2d d3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Discoste_RS_2147833672_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Discoste.RS!MTB"
        threat_id = "2147833672"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Discoste"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 72 de 00 00 70 28 08 00 00 06 28 0d 00 00 06 2a}  //weight: 1, accuracy: High
        $x_1_2 = {03 73 23 00 00 0a 28 24 00 00 0a 6f 25 00 00 0a 6f 26 00 00 0a 73 27 00 00 0a 0a 06 6f 28 00 00 0a 0b de 0d 06 2c 06 06 6f 19 00 00 0a dc 26 de ce}  //weight: 1, accuracy: High
        $x_1_3 = {02 28 07 00 00 06 0a 28 21 00 00 0a 06 6f 22 00 00 0a 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

