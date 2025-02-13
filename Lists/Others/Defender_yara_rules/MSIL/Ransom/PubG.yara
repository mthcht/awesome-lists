rule Ransom_MSIL_PubG_DA_2147780428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/PubG.DA!MTB"
        threat_id = "2147780428"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PubG"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Your Files are all Decrypted" ascii //weight: 5
        $x_5_2 = ".pubg" ascii //weight: 5
        $x_5_3 = "Encrypted" ascii //weight: 5
        $x_1_4 = "GBUPRansomware" ascii //weight: 1
        $x_1_5 = "PUBG Ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

