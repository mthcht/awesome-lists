rule Ransom_MSIL_Cry_DA_2147769061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cry.DA!MTB"
        threat_id = "2147769061"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted by CryRansomware" ascii //weight: 1
        $x_1_2 = "Never open random files" ascii //weight: 1
        $x_1_3 = "cry.Properties.Resources" ascii //weight: 1
        $x_1_4 = "get_EncryptionKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

