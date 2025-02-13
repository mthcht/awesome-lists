rule TrojanDropper_MSIL_BodegunRat_PI_2147899958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/BodegunRat.PI!MTB"
        threat_id = "2147899958"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BodegunRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 49 6d 41 46 75 63 6b 69 6e 67 46 75 64 56 69 72 75 73 5c 49 6d 41 46 75 63 6b 69 6e 67 46 75 64 56 69 72 75 73 5c 6f 62 6a 5c [0-16] 5c 49 6d 41 46 75 63 6b 69 6e 67 46 75 64 56 69 72 75 73 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "ImAFuckingFudVirus.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

