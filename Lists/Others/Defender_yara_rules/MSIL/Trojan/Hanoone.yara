rule Trojan_MSIL_Hanoone_RS_2147833673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hanoone.RS!MTB"
        threat_id = "2147833673"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hanoone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 06 07 28 0d 00 00 06 25 26 0b 1b 17 2d 08 26 14 0b 2b 20 16 0c 08 45 06 00 00 00 8c ff ff ff dc ff ff ff 00 00 00 00 dc ff ff ff cc ff ff ff 06 00 00 00 2b ca}  //weight: 1, accuracy: High
        $x_1_2 = "QU1EIFByb2Nlc3NvciQ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

