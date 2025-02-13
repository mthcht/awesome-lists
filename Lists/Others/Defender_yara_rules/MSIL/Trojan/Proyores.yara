rule Trojan_MSIL_Proyores_A_2147733568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Proyores.A"
        threat_id = "2147733568"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Proyores"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "E:\\Proyectos\\Negociadores\\SqlNet\\obj\\Debug\\SqlNet.pdb" ascii //weight: 5
        $x_5_2 = "E:\\projects\\Negociadores\\SqlNet\\obj\\Debug\\SqlNet.pdb" ascii //weight: 5
        $x_5_3 = "C:\\Documents and Settings\\renzon\\Escritorio\\Proyectos\\Negociadores\\SVN Entendiendo\\Euro-CAFTA\\RoSistema\\SqlNet\\obj\\Debug\\SqlNet.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

