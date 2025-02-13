rule TrojanSpy_MSIL_Husabcar_A_2147689440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Husabcar.A"
        threat_id = "2147689440"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Husabcar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "you can find the owners of unknown telephone numbers easily" wide //weight: 1
        $x_1_2 = "UYGULAMALAR" wide //weight: 1
        $x_1_3 = "turktuccar.com/security.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

