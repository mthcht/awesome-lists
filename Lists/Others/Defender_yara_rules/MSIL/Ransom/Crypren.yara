rule Ransom_MSIL_Crypren_A_2147745841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crypren.A!MTB"
        threat_id = "2147745841"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypren"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\windows.dll" wide //weight: 1
        $x_1_2 = ".ciphered" wide //weight: 1
        $x_1_3 = "\\README_DONT_DELETE.txt" wide //weight: 1
        $x_5_4 = "n5Kq91XTymWeFvGN6DgZu5J2r4O8L9Bl" wide //weight: 5
        $x_5_5 = "nRzY7VKoOyfauQEqEWC2Dx9vlILp0AGB" wide //weight: 5
        $x_5_6 = "8b%CA2o{a}4KGg&75Sz!L$3jcX/96iH*" wide //weight: 5
        $x_5_7 = "0badc0debadc0de10badc0debadc0de1" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

