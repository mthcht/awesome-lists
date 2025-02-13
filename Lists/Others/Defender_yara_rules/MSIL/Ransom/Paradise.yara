rule Ransom_MSIL_Paradise_PA_2147788115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Paradise.PA!MTB"
        threat_id = "2147788115"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Paradise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted," ascii //weight: 1
        $x_1_2 = "#DECRYPT MY FILES#" wide //weight: 1
        $x_1_3 = "\\DecryptionInfo" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

