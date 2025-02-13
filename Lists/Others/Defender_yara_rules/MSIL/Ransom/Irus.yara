rule Ransom_MSIL_Irus_2147729116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Irus"
        threat_id = "2147729116"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Irus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\03capx2x.exe" wide //weight: 4
        $x_4_2 = "\\Suri.exe" wide //weight: 4
        $x_4_3 = "If you remove me , all your files will be deletet" ascii //weight: 4
        $x_4_4 = "SuriProtector(Don't remove)" ascii //weight: 4
        $x_4_5 = "C:\\Users\\Multi\\Desktop\\Tutti i miei progetti\\VB.NET\\WindowsApp1\\WindowsApp1\\obj\\Debug\\WindowsApp1.pdb" ascii //weight: 4
        $x_2_6 = "get_SuriProtector" ascii //weight: 2
        $x_2_7 = "set_SuriProtector" ascii //weight: 2
        $x_2_8 = "m_SuriProtector" ascii //weight: 2
        $x_2_9 = "WindowsApp1.SuriProtector.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_4_*) and 4 of ($x_2_*))) or
            ((5 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

