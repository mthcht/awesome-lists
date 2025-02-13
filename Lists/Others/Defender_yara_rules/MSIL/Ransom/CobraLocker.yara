rule Ransom_MSIL_CobraLocker_DA_2147772561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CobraLocker.DA!MTB"
        threat_id = "2147772561"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobraLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "del C:\\Windows\\System32\\Taskmgr.exe" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "DisableRegistryTools" ascii //weight: 1
        $x_1_4 = "EncryptFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CobraLocker_DB_2147772568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CobraLocker.DB!MTB"
        threat_id = "2147772568"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobraLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your important files are encrypted" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "DisableRegistryTools" ascii //weight: 1
        $x_1_4 = "Cobra_Locker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CobraLocker_DC_2147773262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CobraLocker.DC!MTB"
        threat_id = "2147773262"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobraLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cobra_Locker" ascii //weight: 1
        $x_1_2 = "CreateEncryptor" ascii //weight: 1
        $x_1_3 = "set_FileName" ascii //weight: 1
        $x_1_4 = "GetFolderPath" ascii //weight: 1
        $x_1_5 = "GetFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CobraLocker_DD_2147775152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CobraLocker.DD!MTB"
        threat_id = "2147775152"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobraLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BabaYaga" ascii //weight: 1
        $x_1_2 = "AES_Encrypt" ascii //weight: 1
        $x_1_3 = "del_desktop" ascii //weight: 1
        $x_1_4 = ".locked" ascii //weight: 1
        $x_1_5 = "Start_Encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CobraLocker_DE_2147775153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CobraLocker.DE!MTB"
        threat_id = "2147775153"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobraLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WhoIsLocking" ascii //weight: 1
        $x_1_2 = "ATTENTION!!!.txt" ascii //weight: 1
        $x_1_3 = "RebootReasonNone" ascii //weight: 1
        $x_1_4 = "RunAsDll" ascii //weight: 1
        $x_1_5 = ".locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

