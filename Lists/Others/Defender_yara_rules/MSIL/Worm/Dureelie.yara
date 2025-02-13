rule Worm_MSIL_Dureelie_A_2147685582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Dureelie.A"
        threat_id = "2147685582"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dureelie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autodestruction" ascii //weight: 1
        $x_1_2 = "creerFichier" ascii //weight: 1
        $x_1_3 = "Secacher" ascii //weight: 1
        $x_1_4 = "spreadUsb" ascii //weight: 1
        $x_1_5 = "telecharge" ascii //weight: 1
        $x_1_6 = ":\\autorun.inf" wide //weight: 1
        $x_1_7 = "synSocket" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

