rule Trojan_MSIL_Benin_AH_2147964316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Benin.AH!MTB"
        threat_id = "2147964316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Benin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {61 7e 0a 01 00 04 7b 44 01 00 04 61 7e 76 01 00 04 28 e2 03 00 06 7e 11 00 00 04 7e 93 01 00 04 28 56 04 00 06 74 01 00 00 1b}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

