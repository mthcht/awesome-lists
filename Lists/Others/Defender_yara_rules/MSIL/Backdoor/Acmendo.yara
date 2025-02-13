rule Backdoor_MSIL_Acmendo_A_2147727041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Acmendo.A!bit"
        threat_id = "2147727041"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Acmendo"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://173.249.39.7" wide //weight: 5
        $x_1_2 = "fdowl" wide //weight: 1
        $x_1_3 = "fexc" wide //weight: 1
        $x_1_4 = "prockil" wide //weight: 1
        $x_1_5 = "gtscren" wide //weight: 1
        $x_1_6 = "upld" wide //weight: 1
        $x_1_7 = "kylgs" wide //weight: 1
        $x_1_8 = "destt" wide //weight: 1
        $x_1_9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

