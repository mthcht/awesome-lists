rule TrojanSpy_MSIL_JSSLoader_B_2147814190_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/JSSLoader.B"
        threat_id = "2147814190"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JSSLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 00 4f 00 47 00 49 00 43 00 41 00 4c 00 20 00 44 00 52 00 49 00 56 00 45 00 53 00 3a 00 20 00 27 00 7b 00 30 00 7d 00 27 00 0a 00 7b ?? 31 00 7d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 00 6f 00 67 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 73 00 5e 00 5e 00 5e 00 00 1d 26 00 53 00 79 00 73 00 74 00 65 00 6d 00 49 ?? 6e 00 66 00 6f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6c 00 6f 00 67 00 69 00 63 00 61 00 6c 00 20 00 64 00 72 00 69 00 76 00 65 00 73 00 22 00 3a 00 20 00 22 00 7b ?? 30 00 7d 00 22}  //weight: 1, accuracy: Low
        $x_1_4 = {6c 00 6f 00 67 00 69 00 63 00 61 00 6c 00 20 00 64 00 72 00 69 00 76 00 65 00 73 00 22 00 3a 00 20 00 22 00 00 21 22 ?? 73 00 79 00 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

