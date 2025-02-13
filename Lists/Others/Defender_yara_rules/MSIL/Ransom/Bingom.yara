rule Ransom_MSIL_Bingom_DA_2147781636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Bingom.DA!MTB"
        threat_id = "2147781636"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bingom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZinzinVirus" ascii //weight: 1
        $x_1_2 = "TamperProtection" ascii //weight: 1
        $x_1_3 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_4 = "DisableTaskMgr" ascii //weight: 1
        $x_1_5 = "bytesToBeEncrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

