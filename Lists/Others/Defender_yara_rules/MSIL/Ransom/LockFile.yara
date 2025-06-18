rule Ransom_MSIL_LockFile_PDZ_2147943903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockFile.PDZ!MTB"
        threat_id = "2147943903"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Your Files Have Been Encrypted" wide //weight: 3
        $x_3_2 = "is locked and could not be encrypted" wide //weight: 3
        $x_2_3 = "Once you have made payment, you will be sent a decryptor" wide //weight: 2
        $x_2_4 = "Do not bother trying to decrypt the files on your own" wide //weight: 2
        $x_1_5 = "If you wish to learn more, look for a README.txt on your desktop" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

