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

rule Ransom_MSIL_LockFile_AMTB_2147966847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockFile!AMTB"
        threat_id = "2147966847"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockFile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "NyanWare.Properties.Resources" ascii //weight: 2
        $x_2_2 = "NyanWare.pdb" ascii //weight: 2
        $x_1_3 = "get_bitcoin" ascii //weight: 1
        $x_1_4 = " OOPS! ALL YOUR FILES ARE ENCRYPTED!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_LockFile_SX_2147968170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockFile.SX!MTB"
        threat_id = "2147968170"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "Ransomware.exe" ascii //weight: 30
        $x_20_2 = "your important files are encrypted!" ascii //weight: 20
        $x_10_3 = "Send {0} USD in Bitcoin" ascii //weight: 10
        $x_10_4 = "Key accepted. Decrypting files" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

