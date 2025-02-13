rule Backdoor_MSIL_Rurktar_A_2147722875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Rurktar.A"
        threat_id = "2147722875"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rurktar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RCSU.exe" wide //weight: 1
        $x_1_2 = "RCS.log" wide //weight: 1
        $x_1_3 = "\\R_C_S.ini" wide //weight: 1
        $x_1_4 = "\\RCS.ini" wide //weight: 1
        $x_1_5 = "80.78.251.138" wide //weight: 1
        $x_1_6 = "80.78.251.148" wide //weight: 1
        $x_1_7 = "89.250.146.109" wide //weight: 1
        $x_1_8 = "type*updater" wide //weight: 1
        $x_1_9 = "?recivefile*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

