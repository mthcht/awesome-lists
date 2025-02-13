rule Ransom_MSIL_PoC_DA_2147774385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/PoC.DA!MTB"
        threat_id = "2147774385"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PoC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PoC Ransomware" ascii //weight: 1
        $x_1_2 = "EncryptDir" ascii //weight: 1
        $x_1_3 = "EncryptFile" ascii //weight: 1
        $x_1_4 = "get_Extension" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

