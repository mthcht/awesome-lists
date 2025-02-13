rule Ransom_MSIL_BBRansomware_DA_2147780370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BBRansomware.DA!MTB"
        threat_id = "2147780370"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BBRansomware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BB ransomware" ascii //weight: 1
        $x_1_2 = ".encrypted" ascii //weight: 1
        $x_1_3 = "Wrong code. Hahaha" ascii //weight: 1
        $x_1_4 = "Success Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

