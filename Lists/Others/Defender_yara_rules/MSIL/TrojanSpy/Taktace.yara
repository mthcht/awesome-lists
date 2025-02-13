rule TrojanSpy_MSIL_Taktace_A_2147690024_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Taktace.A"
        threat_id = "2147690024"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taktace"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Q-1-q" wide //weight: 1
        $x_1_2 = "Q-2-q" wide //weight: 1
        $x_1_3 = "Q-3-q" wide //weight: 1
        $x_1_4 = "TRACK AND TRACE" wide //weight: 1
        $x_1_5 = {74 72 61 63 6b 61 6e 64 74 72 61 63 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 6e 69 70 49 6e 74 6f 53 75 62 64 6f 6d 61 69 6e 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {73 65 6e 64 44 4e 53 73 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_8 = {67 65 74 44 72 69 76 65 73 43 6f 6e 74 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {62 79 74 65 73 5f 70 65 72 5f 64 6e 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

