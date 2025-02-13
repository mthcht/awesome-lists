rule Ransom_MSIL_Bytelocker_DA_2147775156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Bytelocker.DA!MTB"
        threat_id = "2147775156"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bytelocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bytelocker" ascii //weight: 1
        $x_1_2 = "CreateEncryptor" ascii //weight: 1
        $x_1_3 = "ToBase64String" ascii //weight: 1
        $x_1_4 = "GetExtension" ascii //weight: 1
        $x_1_5 = "get_CurrentDomain" ascii //weight: 1
        $x_1_6 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

