rule TrojanDropper_MSIL_Bladabindi_AH_2147725844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Bladabindi.AH!bit"
        threat_id = "2147725844"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 00 61 00 63 00 6b 00 65 00 64 00 00 ?? 74 00 68 00 65 00 64 00 61 00 79 00 73 00 2e}  //weight: 2, accuracy: Low
        $x_1_2 = "I.A.M.B.A.C.K" wide //weight: 1
        $x_1_3 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_2_4 = {5c 57 6f 72 6d (20|2d) 43 6c 69 65 6e 74 (20|2d) 4e 6f 72 6d 61 6c 44 6f 77 6e 6c 6f 61 64 65 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_MSIL_Bladabindi_NIT_2147922107_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Bladabindi.NIT!MTB"
        threat_id = "2147922107"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 01 00 00 04 07 6f ?? 00 00 0a 0c 08 6f ?? 00 00 0a 13 05 11 05 2c 29 07 06 fe 01 16 fe 01 13 06 11 06 2c 17 7e 01 00 00 04 06 7e 01 00 00 04 07 6f ?? 00 00 0a 6f ?? 00 00 0a 00 00 06 17 58 0a 00 00 07 17 58 0b 07 11 04 13 07 11 07 31 b0}  //weight: 2, accuracy: Low
        $x_1_2 = "\\obj\\Debug\\Software.pdb" ascii //weight: 1
        $x_1_3 = "GetResourceString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

