rule TrojanDropper_MSIL_KerrDown_C_2147744097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/KerrDown.C!dha"
        threat_id = "2147744097"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KerrDown"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "F40B130D-2E08-4D13-BD0E-7ED16264C101" ascii //weight: 3
        $x_2_2 = "shell_w32.dll" ascii //weight: 2
        $x_1_3 = "Compomented" ascii //weight: 1
        $x_1_4 = "regsvcser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

