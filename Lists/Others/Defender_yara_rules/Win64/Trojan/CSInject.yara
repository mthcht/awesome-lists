rule Trojan_Win64_CSInject_AW_2147836669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CSInject.AW!MTB"
        threat_id = "2147836669"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CSInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AES Process Hollowing.exe" ascii //weight: 1
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "ResumeThread" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

