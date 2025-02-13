rule Ransom_MSIL_Exocrypt_DA_2147781551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Exocrypt.DA!MTB"
        threat_id = "2147781551"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exocrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your Personal Files Are Encrypted" ascii //weight: 1
        $x_1_2 = "Exocrypt XTC" ascii //weight: 1
        $x_1_3 = "DO_NOT_DELETE" ascii //weight: 1
        $x_1_4 = ".xtc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

