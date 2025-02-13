rule VirTool_MSIL_Splori_A_2147689145_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Splori.A"
        threat_id = "2147689145"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Splori"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {52 75 6e 50 45 00}  //weight: 10, accuracy: High
        $x_10_2 = {49 6e 6a 65 63 74 50 45 00}  //weight: 10, accuracy: High
        $x_10_3 = {68 69 64 5f 73 74 61 72 74 00}  //weight: 10, accuracy: High
        $x_1_4 = {49 73 41 6e 75 62 69 73 53 61 6e 64 62 6f 78 00}  //weight: 1, accuracy: High
        $x_1_5 = {49 73 43 57 53 61 6e 64 62 6f 78 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 73 4e 6f 72 6d 61 6e 53 61 6e 64 62 6f 78 00}  //weight: 1, accuracy: High
        $x_1_7 = {49 73 53 61 6e 64 62 6f 78 69 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {49 73 53 75 6e 62 65 6c 74 53 61 6e 64 62 6f 78 00}  //weight: 1, accuracy: High
        $x_1_9 = {49 73 57 69 72 65 73 68 61 72 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

