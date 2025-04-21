rule Trojan_MSIL_Johnnie_AJO_2147939558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Johnnie.AJO!MTB"
        threat_id = "2147939558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Johnnie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 da 0c 0b 2b 30 03 07 91 20 ff 00 00 00 fe 01 16 fe 01 13 05 11 05 2c 12 03 0d 09 07 13 04 11 04 09 11 04 91 17 d6 b4 9c 2b 05 00 03 07 16 9c 00 00 07 17 d6 0b 07 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

