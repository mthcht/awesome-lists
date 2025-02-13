rule Ransom_MSIL_Rapax_YAA_2147914748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Rapax.YAA!MTB"
        threat_id = "2147914748"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rapax"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rapax Ransomware" ascii //weight: 1
        $x_1_2 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
        $x_1_3 = "DECRYPTION KEY" ascii //weight: 1
        $x_1_4 = "PAY A RANSOM" ascii //weight: 1
        $x_1_5 = "Purchase Bitcoin" ascii //weight: 1
        $x_1_6 = "restore access to your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

