rule Ransom_MSIL_Goodlock_YAC_2147946454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Goodlock.YAC!MTB"
        threat_id = "2147946454"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Goodlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GoodLock.exe" ascii //weight: 1
        $x_1_2 = "GoodLock.Info.resources" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "DecryptAllEncryptedFiles" ascii //weight: 1
        $x_1_6 = "ENCRYPT_DESKTOP" ascii //weight: 1
        $x_2_7 = "ENCRYPT_PICTURES" ascii //weight: 2
        $x_10_8 = "been encrypted by good" wide //weight: 10
        $x_10_9 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 47 00 6f 00 6f 00 64 00 4c 00 6f 00 63 00 6b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

