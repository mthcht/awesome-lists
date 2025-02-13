rule Ransom_MSIL_EDA_DA_2147793545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/EDA.DA!MTB"
        threat_id = "2147793545"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EDA"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ransom.jpg" ascii //weight: 1
        $x_1_2 = "Ransomware\\eda2\\eda2-master" ascii //weight: 1
        $x_1_3 = "bytesToBeEncrypted" ascii //weight: 1
        $x_1_4 = "aesencrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

