rule Ransom_MSIL_LockFolder_DA_2147771534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockFolder.DA!MTB"
        threat_id = "2147771534"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockFolder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encryption done!" ascii //weight: 1
        $x_1_2 = "CreateEncryptor" ascii //weight: 1
        $x_1_3 = "FileEncrypt" ascii //weight: 1
        $x_1_4 = "LockFolder.pdb" ascii //weight: 1
        $x_1_5 = "LockFolder.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

