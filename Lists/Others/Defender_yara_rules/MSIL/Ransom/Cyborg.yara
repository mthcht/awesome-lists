rule Ransom_MSIL_Cyborg_SA_2147745225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cyborg.SA!MSR"
        threat_id = "2147745225"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cyborg"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Cyborg Builder Ransomware" ascii //weight: 2
        $x_2_2 = "syborg1finf.exe" ascii //weight: 2
        $x_1_3 = "get_SpecialDirectories" ascii //weight: 1
        $x_1_4 = "CryptoStreamMode" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
        $x_1_6 = "Cracked" ascii //weight: 1
        $x_1_7 = "WasHere" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

