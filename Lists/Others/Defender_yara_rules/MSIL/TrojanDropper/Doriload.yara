rule TrojanDropper_MSIL_Doriload_A_2147628365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Doriload.A"
        threat_id = "2147628365"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Doriload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 11 00 00 0a 26 09 6f 12 00 00 0a 72 1b 00 00 70 28 09 00 00 0a 72 25 00 00 70 28 0a 00 00 0a 28 13 00 00 0a de 03 26 de 00 2a [0-32] 02 28 14 00 00 0a 2a ?? ?? ?? ?? 4d 5a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

