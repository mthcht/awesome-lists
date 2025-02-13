rule TrojanDropper_MSIL_Gendwndrop_D_2147718090_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Gendwndrop.D!bit"
        threat_id = "2147718090"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gendwndrop"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 19 00 00 0a 0c 08 06 07 03 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 6f ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "Protector" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

