rule Ransom_MSIL_Charity_YAA_2147906800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Charity.YAA!MTB"
        threat_id = "2147906800"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Charity"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CHARITY" wide //weight: 1
        $x_1_2 = "RANSOM_NOTE.txt" wide //weight: 1
        $x_1_3 = "encrypted and removed" wide //weight: 1
        $x_1_4 = "appreciate your donation" wide //weight: 1
        $x_1_5 = "recover my files" ascii //weight: 1
        $x_1_6 = "Ransom\\Charity-master" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

