rule Ransom_MSIL_ZeroLocker_DA_2147770168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ZeroLocker.DA!MTB"
        threat_id = "2147770168"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZeroLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZeroLocker" ascii //weight: 1
        $x_1_2 = "Files successfully decrypted!" ascii //weight: 1
        $x_1_3 = "ZeroLocker.Resources" ascii //weight: 1
        $x_1_4 = "ZeroLocker will be now removed from your Computer!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

