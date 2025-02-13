rule VirTool_MSIL_Inject_2147693414_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Inject"
        threat_id = "2147693414"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Inject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 35 3a 6f 42 3e 3f 55 64 3d 49 3b 2a 3e 2c 3f 57 2f 2d 39 36 68 64 60 00 41 74 74 72 69 62 75 74 65}  //weight: 1, accuracy: High
        $x_1_2 = "babiggboy.ddns.net" ascii //weight: 1
        $x_1_3 = "modem killa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Inject_2147693414_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Inject"
        threat_id = "2147693414"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Inject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 75 72 69 49 6e 69 6d 61 2e 65 78 65 00 66 75 72 69 49 6e 69 6d 61 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 00 69 00 74 00 6d 00 61 00 74 00 ?? ?? 67 00 72 00 61 00 73 00 75 00 74 00 61 00 ?? ?? 66 00 75 00 72 00 69 00 49 00 6e 00 69 00 6d 00 61 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = "cumte.tambal" wide //weight: 1
        $x_1_4 = "CumteTambal" ascii //weight: 1
        $x_1_5 = {13 05 11 05 13 06 09 11 06 61 13 07 11 07 d1 13 08 06 11 08 6f 35 00 00 0a 26 00 07 13 09 11 09 17 58 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

