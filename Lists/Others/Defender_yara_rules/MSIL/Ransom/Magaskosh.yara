rule Ransom_MSIL_Magaskosh_MA_2147889492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Magaskosh.MA!MTB"
        threat_id = "2147889492"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Magaskosh"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MagasFinisher.pdb" ascii //weight: 1
        $x_1_2 = "MagasFinisher.Properties" ascii //weight: 1
        $x_1_3 = "ce6eaf7c-3ab4-4105-b842-9fc3ea3ff9aa" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

