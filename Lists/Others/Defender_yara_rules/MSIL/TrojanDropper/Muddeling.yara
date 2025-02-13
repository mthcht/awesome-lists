rule TrojanDropper_MSIL_Muddeling_A_2147740856_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Muddeling.A!dha"
        threat_id = "2147740856"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Muddeling"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "35d772fb-d2ed-49bb-a4ca-ab55f4ffa497" ascii //weight: 2
        $x_1_2 = "\\Scr.js" ascii //weight: 1
        $x_1_3 = "\\Save the Date G20 Digital Economy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

