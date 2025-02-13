rule Trojan_MSIL_Jigsaw_PSNE_2147846479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jigsaw.PSNE!MTB"
        threat_id = "2147846479"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jigsaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {26 38 c2 f8 ff ff 11 16 17 58 13 16 11 1a 20 38 3b 25 12 5a 20 8a 58 b4 76 61 38 a9 f8 ff ff 1f 10 8d 24 00 00 01 13 14 1f 10 8d 24 00 00 01 13 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

