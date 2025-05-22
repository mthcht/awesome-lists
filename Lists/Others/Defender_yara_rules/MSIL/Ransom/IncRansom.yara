rule Ransom_MSIL_IncRansom_YAD_2147942008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/IncRansom.YAD!MTB"
        threat_id = "2147942008"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IncRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ransomeware.ps1" ascii //weight: 10
        $x_5_2 = "FILES HAVE BEEN ENCRYPTED" ascii //weight: 5
        $x_5_3 = "encrypted with military-grade encryption" ascii //weight: 5
        $x_1_4 = "PAY THE RANSOM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

