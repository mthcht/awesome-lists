rule TrojanDropper_MSIL_Drogcatchaft_A_2147640623_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Drogcatchaft.A"
        threat_id = "2147640623"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Drogcatchaft"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "The_Godfather_Stub.Form" ascii //weight: 5
        $x_1_2 = "Ed1H3r0" wide //weight: 1
        $x_1_3 = "\\Crypted.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

