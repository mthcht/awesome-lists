rule TrojanDropper_MSIL_Crysan_AAT_2147923699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Crysan.AAT!MTB"
        threat_id = "2147923699"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 15 28 ?? ?? ?? 06 26 11 06 20 ?? ?? ?? ?? 5a 20 ?? ?? ?? ?? 61 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

