rule Ransom_Win64_GoAgendaCrypt_AD_2147849032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GoAgendaCrypt.AD!MTB"
        threat_id = "2147849032"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GoAgendaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Y25VsIgRDr" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Public\\enc.exe" ascii //weight: 1
        $x_1_3 = "EnableLinkedConnections" ascii //weight: 1
        $x_1_4 = "LogonUserW" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

