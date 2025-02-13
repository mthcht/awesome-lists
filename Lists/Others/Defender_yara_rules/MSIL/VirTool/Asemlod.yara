rule VirTool_MSIL_Asemlod_A_2147696114_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Asemlod.A"
        threat_id = "2147696114"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Asemlod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 5a 13 ?? 11 ?? 17 58 13 ?? 11 ?? 11 ?? 32 ?? 09 11 ?? 07 11 ?? 91 5a 58 0d 11 ?? 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Asemlod_B_2147696302_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Asemlod.B"
        threat_id = "2147696302"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Asemlod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 19 5a 18 58 12 ?? 28 ?? ?? ?? 06 9c 06 07 19 5a 17 58 12 ?? 28 ?? ?? ?? 06 9c 06 07 19 5a 12 ?? 28 ?? ?? ?? 06 9c 07 17 58}  //weight: 1, accuracy: Low
        $x_1_2 = {19 d8 18 d6 12 ?? 28 ?? ?? ?? ?? 9c 09 11 ?? 19 d8 17 d6 12 ?? 28 ?? ?? ?? ?? 9c 09 11 ?? 19 d8 12 ?? 28 ?? ?? ?? ?? 9c 11 ?? 17 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_MSIL_Asemlod_C_2147696303_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Asemlod.C"
        threat_id = "2147696303"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Asemlod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 00 2e 00 38 00 4f 00 84 76 84 76 79 00 84 76 84 76 84 76 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Asemlod_D_2147696308_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Asemlod.D"
        threat_id = "2147696308"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Asemlod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4#D#5#A#9#0#0#0#0#3#0#0#0#0#0#0#0#4#0#0#0#0#0#0#F#F#F#F#" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

