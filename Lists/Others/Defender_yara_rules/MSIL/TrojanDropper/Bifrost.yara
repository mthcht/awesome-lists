rule TrojanDropper_MSIL_Bifrost_MVA_2147900921_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Bifrost.MVA!MTB"
        threat_id = "2147900921"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bifrost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 35 00 00 70 09 28 2c 00 00 0a 28 2d 00 00 0a 6f 27 00 00 0a 74 0a 00 00 1b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

