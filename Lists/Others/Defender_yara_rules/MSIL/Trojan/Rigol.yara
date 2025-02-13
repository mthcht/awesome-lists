rule Trojan_MSIL_Rigol_A_2147735089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rigol.A"
        threat_id = "2147735089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rigol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "84e31856-683b-41c0-81dd-a02d8b795026" ascii //weight: 1
        $x_1_2 = "\\exeruner\\exeruner\\obj\\Debug\\exeruner.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

