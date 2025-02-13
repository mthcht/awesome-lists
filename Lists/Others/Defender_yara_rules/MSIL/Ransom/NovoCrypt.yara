rule Ransom_MSIL_NovoCrypt_MK_2147788120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NovoCrypt.MK!MTB"
        threat_id = "2147788120"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NovoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Ransomware" ascii //weight: 10
        $x_10_2 = "Ransomware.Properties" ascii //weight: 10
        $x_10_3 = "your important files have been encrypted" ascii //weight: 10
        $x_10_4 = "your files will be permamently shredded" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

