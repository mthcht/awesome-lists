rule Backdoor_MSIL_Fkonrat_A_2147721594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Fkonrat.A!bit"
        threat_id = "2147721594"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fkonrat"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Fkn0wned Rat" ascii //weight: 3
        $x_2_2 = "downloaded and executed" wide //weight: 2
        $x_2_3 = "fdfgdfgsdgdfgdfg" wide //weight: 2
        $x_1_4 = "\\svchosts.exe" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

