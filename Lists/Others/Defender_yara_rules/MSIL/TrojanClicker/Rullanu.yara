rule TrojanClicker_MSIL_Rullanu_A_2147662114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Rullanu.A"
        threat_id = "2147662114"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rullanu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 05 00 00 70 28 ?? 00 00 ?? 72 13 00 00 70 28 ?? 00 00 ?? 28 ?? 00 00 ?? 0a [0-5] 06 72 4b 00 00 70 [0-5] 16 fe 01 0b 07 2d ?? 00 [0-5] 17 28 ?? 00 00 ?? 00 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {7e 02 00 00 04 7e ?? 00 00 0a 17 ?? ?? ?? ?? ?? 16 fe 01 0c 08 2d ?? 00 28 ?? 00 00 06 00 [0-10] 1f 1c 28 ?? 00 00 ?? 72 01 00 00 70 7e ?? 00 00 04 28 ?? 00 00 ?? 0a 28 ?? 00 00 06 00 7e ?? 00 00 04 06 28 ?? 00 00 06 00 [0-5] 28 ?? 00 00 ?? 00 [0-5] 16 28 ?? 00 00 ?? 00 73 ?? 00 00 06 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

