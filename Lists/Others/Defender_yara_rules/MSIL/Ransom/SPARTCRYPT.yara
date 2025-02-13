rule Ransom_MSIL_SPARTCRYPT_DA_2147780324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SPARTCRYPT.DA!MTB"
        threat_id = "2147780324"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SPARTCRYPT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files have been encrypted" ascii //weight: 1
        $x_1_2 = "How_To_Restore_Your_Files" ascii //weight: 1
        $x_1_3 = ".Encrypted" ascii //weight: 1
        $x_1_4 = "EncryptedFilesList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

