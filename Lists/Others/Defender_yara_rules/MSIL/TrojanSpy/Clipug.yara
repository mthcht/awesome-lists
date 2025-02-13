rule TrojanSpy_MSIL_Clipug_A_2147686620_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Clipug.A"
        threat_id = "2147686620"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clipug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 08 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0a 06 72 ?? ?? 00 70 16 28 ?? 00 00 0a 0b 07 13 06 11 06 2c 15 28 08 00 00 06 6f ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a}  //weight: 2, accuracy: Low
        $x_1_2 = {28 08 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0a 06 72 ?? ?? 00 70 16 28 ?? 00 00 0a 06 72 ?? ?? 00 70 16 28 ?? 00 00 0a 60 06 72 ?? ?? 00 70 16 28 ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {60 0b 07 13 06 11 06 2c 15 28 08 00 00 06 6f ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_5_4 = "##########################" wide //weight: 5
        $x_5_5 = "## #### #### #### #### #### ####" wide //weight: 5
        $x_5_6 = {67 65 74 5f 43 6c 69 70 62 6f 61 72 64 00 47 65 74 54 65 78 74 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

