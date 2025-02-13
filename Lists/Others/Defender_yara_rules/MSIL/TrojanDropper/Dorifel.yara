rule TrojanDropper_MSIL_Dorifel_AB_2147908981_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Dorifel.AB!MTB"
        threat_id = "2147908981"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dorifel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 38 00 00 0a 06 8e b7 18 da 16 da 17 d6 6b 28 3b 00 00 0a 5a 28 3c 00 00 0a 22 00 00 80 3f 58 6b 6c 28 3d 00 00 0a b7 13 04 08 06 11 04 93 6f 3e 00 00 0a 26 09 17 d6 0d 09 11 05}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

