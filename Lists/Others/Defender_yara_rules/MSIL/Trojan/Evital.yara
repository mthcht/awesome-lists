rule Trojan_MSIL_Evital_AEV_2147853343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Evital.AEV!MTB"
        threat_id = "2147853343"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Evital"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 14 11 06 11 14 19 6f 8d 00 00 0a 11 14 17 6f 8d 00 00 0a 72 cf 15 00 70 11 14 18 6f 8d 00 00 0a 28 07 00 00 0a 11 14 16 6f 8d 00 00 0a 11 09 6f 64 00 00 06 11 0b 6f 79 00 00 06 28 f4 00 00 06 6f 08 00 00 0a 12 0f 28 8e 00 00 0a 2d aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

