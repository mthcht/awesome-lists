rule Trojan_MSIL_Gapmosoc_A_2147707661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gapmosoc.A"
        threat_id = "2147707661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gapmosoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GamesofPC\\SetupR" wide //weight: 1
        $x_1_2 = "Setup\\obj\\Debug\\FIFA 16.pdb" wide //weight: 1
        $x_4_3 = "/goo.gl/dRmF6C" wide //weight: 4
        $x_4_4 = "/goo.gl/7ZzPGe" wide //weight: 4
        $x_4_5 = "/goo.gl/XoTB0K" wide //weight: 4
        $x_4_6 = "/goo.gl/PszMzr" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

