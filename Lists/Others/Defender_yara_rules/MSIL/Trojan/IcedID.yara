rule Trojan_MSIL_IcedID_MA_2147893226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/IcedID.MA!MTB"
        threat_id = "2147893226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {13 04 7e 01 00 00 04 7b 0b 00 00 0a 16 28 11 00 00 0a 13 05 02 11 05 11 04 28 12 00 00 0a 72 3b 00 00 70 72 55 00 00 70 11 04 72 59 00 00 70 28 13 00 00 0a 28 14 00 00 0a 26 de 03}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

