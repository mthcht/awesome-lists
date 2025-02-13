rule Worm_MSIL_Azaak_A_2147709380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Azaak.A"
        threat_id = "2147709380"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azaak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Razvan\\Desktop\\Oh yeah\\photo\\photo\\obj\\Debug\\leagueoflegends.pdb" ascii //weight: 10
        $x_5_2 = "\\autorun.inf" wide //weight: 5
        $x_5_3 = "shellexecute=" wide //weight: 5
        $x_3_4 = "\\\\KaZaA\\WINODWSUpd.exe" wide //weight: 3
        $x_1_5 = "\\shit.bmp" wide //weight: 1
        $x_1_6 = "USBinstaller.exe" wide //weight: 1
        $x_1_7 = "temporaries.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

