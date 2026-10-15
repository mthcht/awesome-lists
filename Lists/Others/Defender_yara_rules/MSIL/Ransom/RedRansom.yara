rule Ransom_MSIL_RedRansom_AMTB_2147980360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/RedRansom!AMTB"
        threat_id = "2147980360"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedRansom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "README_STOPCHEATING.txt" ascii //weight: 2
        $x_2_2 = "RedRansom.pdb" ascii //weight: 2
        $x_2_3 = "R3dR4ns0m_UltraSecret_2024_666" ascii //weight: 2
        $x_1_4 = ".STOPCHEATING" ascii //weight: 1
        $x_1_5 = "Global\\RedRansom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

