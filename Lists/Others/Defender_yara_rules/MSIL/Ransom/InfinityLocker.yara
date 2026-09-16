rule Ransom_MSIL_InfinityLocker_AMTB_2147978239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/InfinityLocker!AMTB"
        threat_id = "2147978239"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InfinityLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "InfinityL0cker.Properties" ascii //weight: 2
        $x_2_2 = "InfinityL0cker.pdb" ascii //weight: 2
        $x_2_3 = "HIFAGGOT" ascii //weight: 2
        $x_1_4 = "ransom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

