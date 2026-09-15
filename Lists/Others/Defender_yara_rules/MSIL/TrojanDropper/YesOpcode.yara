rule TrojanDropper_MSIL_YesOpcode_C_2147978174_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/YesOpcode.C!dha"
        threat_id = "2147978174"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "YesOpcode"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 20 5d a3 00 00 fe 02 16 fe 01 2b 01 17 00 13 ?? 11 ?? 3a ?? 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8e 69 20 1c aa 00 00 fe 02 16 fe 01 2b 01 17 00 13 ?? 11 ?? 3a ?? 02 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8e 69 20 00 c8 00 00 fe 02 16 fe 01 2b 01 17 00 13 ?? 11 ?? 3a ?? 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

