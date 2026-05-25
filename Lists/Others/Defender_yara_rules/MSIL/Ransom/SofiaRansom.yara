rule Ransom_MSIL_SofiaRansom_AMTB_2147970086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SofiaRansom!AMTB"
        threat_id = "2147970086"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SofiaRansom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SofiaRansome.Properties" ascii //weight: 1
        $x_2_2 = "No encrypted (.sofia) files found on your Desktop" ascii //weight: 2
        $x_2_3 = "\\Desktop\\SofiaRansome\\obj\\Release\\net8.0-windows\\win-x64\\SofiaRansome.pdb" ascii //weight: 2
        $x_1_4 = "SofiaRansome_Secure_Salt_2026" ascii //weight: 1
        $x_1_5 = "SofiaRansome.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

