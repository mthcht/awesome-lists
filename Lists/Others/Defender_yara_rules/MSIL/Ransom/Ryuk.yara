rule Ransom_MSIL_Ryuk_ARA_2147919300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ryuk.ARA!MTB"
        threat_id = "2147919300"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ryukransom" ascii //weight: 2
        $x_2_2 = "RyukEncrypter" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Ryuk_MX_2147920224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ryuk.MX!MTB"
        threat_id = "2147920224"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ryuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Ryuk Ransomware" ascii //weight: 5
        $x_1_2 = "Encrypted$" ascii //weight: 1
        $x_5_3 = "RyukEncrypter" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

