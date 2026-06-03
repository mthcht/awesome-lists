rule Trojan_MSIL_Egairtigado_SN_2147970857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Egairtigado.SN!MTB"
        threat_id = "2147970857"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Egairtigado"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 72 7a 03 00 70 72 92 03 00 70 03 28 37 00 00 0a 28 6e 00 00 0a 06 28 ce 00 00 0a 08 17 58 0c 08 07 8e 69 32 bd}  //weight: 5, accuracy: High
        $x_5_2 = {72 b4 03 00 70 03 72 0c 04 00 70 28 70 00 00 0a 0d 08 28 cf 00 00 0a 73 d0 00 00 0a 25 09 6f d1 00 00 0a 13 04 08 11 04 28 d2 00 00 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

