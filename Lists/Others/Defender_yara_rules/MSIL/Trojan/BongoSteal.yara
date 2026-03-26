rule Trojan_MSIL_BongoSteal_AMTB_2147965610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BongoSteal!AMTB"
        threat_id = "2147965610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BongoSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BongoSteal.VM" ascii //weight: 1
        $x_1_2 = "repos\\BongoSteal\\BongoSteal\\obj\\Debug\\BongoSteal.pdb" ascii //weight: 1
        $x_1_3 = "sal.rosenburg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

