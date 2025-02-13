rule Ransom_MSIL_AESLocker_DA_2147775151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/AESLocker.DA!MTB"
        threat_id = "2147775151"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AESLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AES-Locker" ascii //weight: 1
        $x_1_2 = "EncryptKey" ascii //weight: 1
        $x_1_3 = "EncryptAES" ascii //weight: 1
        $x_1_4 = ".locked" ascii //weight: 1
        $x_1_5 = ".iask.in" ascii //weight: 1
        $x_1_6 = "lock.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

