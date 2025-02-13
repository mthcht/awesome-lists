rule Ransom_MSIL_Invader_MA_2147888125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Invader.MA!MTB"
        threat_id = "2147888125"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Invader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "uluBgXtWgrL1J51vrN.VE4RkDjh5NJQIifVR5" ascii //weight: 2
        $x_2_2 = "jhsIn2ICirN5bEZO4q.9Z9JGY34683HQn7fom" ascii //weight: 2
        $x_1_3 = "7738da72-1133-4acf-a6b2-f3512bae9b2a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

