rule TrojanClicker_MSIL_Clifoca_2147687751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Clifoca"
        threat_id = "2147687751"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Clifoca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$4e412abb-ff27-4b39-8aa0-57778e363286" ascii //weight: 1
        $x_1_2 = "/Nueva carpeta.exe" wide //weight: 1
        $x_1_3 = "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/Special.exe" wide //weight: 1
        $x_1_4 = "http://foldcash.x10.mx/" wide //weight: 1
        $x_1_5 = "c:\\Users\\AlvarSoft\\Documents\\Visual Studio 2013\\Projects\\FolderCash\\FolderCash\\obj\\Release\\FolderCash.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

