rule TrojanDropper_MSIL_Buqzits_A_2147629855_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Buqzits.A"
        threat_id = "2147629855"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Buqzits"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 09 1e 0c 28 ?? ?? ?? ?? 2b 03 1f 0a 0c 1f 0c 0c 02 7b ?? ?? ?? ?? 1a 9a 28 ?? ?? ?? ?? 2c 0b 1f 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {69 64 00 4b 61 73 70 65 72 6b 79 00 56 50 43 00 56 4d 57 61 72 65 00 53 61 6e 64 62 6f 78 69 65 00 48 69 4a 61 63 6b 54 68 69 73 00 67 65 74 44 65 76 69 63 65 73 00 52 43 34 00}  //weight: 1, accuracy: High
        $x_1_3 = "FUCK@I@OWN@THIS@SHIZ!@" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

