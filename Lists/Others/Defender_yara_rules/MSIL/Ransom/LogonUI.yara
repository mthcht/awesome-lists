rule Ransom_MSIL_LogonUI_DA_2147772879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LogonUI.DA!MTB"
        threat_id = "2147772879"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LogonUI"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LogonUIRansomware" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "Enter Decryption Key" ascii //weight: 1
        $x_1_4 = "iconfinder_lock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

