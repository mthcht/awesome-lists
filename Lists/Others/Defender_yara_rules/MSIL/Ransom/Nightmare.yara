rule Ransom_MSIL_Nightmare_ARA_2147914449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Nightmare.ARA!MTB"
        threat_id = "2147914449"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nightmare"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SilentNightmare Ransomware" wide //weight: 2
        $x_2_2 = "Complete encryption" wide //weight: 2
        $x_2_3 = "Hyper-V" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

