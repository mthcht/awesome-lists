rule TrojanDropper_MSIL_QuasarRAT_P_2147955996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/QuasarRAT.P!AMTB"
        threat_id = "2147955996"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 8f 0a 00 00 01 25 71 0a 00 00 01 7e 01 00 00 04 07 7e 01 00 00 04 8e 69 5d 91 61 d2 81 0a 00 00 01 07 17 58 0b 07 06 8e 69 32 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

