rule Ransom_MSIL_OnyxLocker_DA_2147770166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/OnyxLocker.DA!MTB"
        threat_id = "2147770166"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OnyxLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OnyxLocker" ascii //weight: 1
        $x_1_2 = "RECOVERY INSTRUCTIONS" ascii //weight: 1
        $x_1_3 = "OnyxLocker.Classes" ascii //weight: 1
        $x_1_4 = "WW91IHNob3VsZCByZXBsYWNlIHRoaXMgbWVzc2FnZSB3aXRoIHRoZSBvbmUgeW91IHdhbnQgeW91ciB1c2VycyB0byBzZWUu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_OnyxLocker_DB_2147771533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/OnyxLocker.DB!MTB"
        threat_id = "2147771533"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OnyxLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OnyxLocker" ascii //weight: 1
        $x_1_2 = "DirWalker" ascii //weight: 1
        $x_1_3 = "WriteMessageToDesktop" ascii //weight: 1
        $x_1_4 = "get_EncryptionKey" ascii //weight: 1
        $x_1_5 = "get_CurrentDomain" ascii //weight: 1
        $x_1_6 = "XxteaEncryptionProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_OnyxLocker_DC_2147772855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/OnyxLocker.DC!MTB"
        threat_id = "2147772855"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OnyxLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RECOVERY INSTRUCTIONS" ascii //weight: 1
        $x_1_2 = ".destroyed" ascii //weight: 1
        $x_1_3 = "directoryWalker" ascii //weight: 1
        $x_1_4 = "get_FileParser" ascii //weight: 1
        $x_1_5 = "WriteFileBytes" ascii //weight: 1
        $x_1_6 = "WriteMessageToDocuments" ascii //weight: 1
        $x_1_7 = "ShowWindow" ascii //weight: 1
        $x_1_8 = "get_EncryptionKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

