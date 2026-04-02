rule Ransom_Win64_Uragan_YBF_2147966128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Uragan.YBF!MTB"
        threat_id = "2147966128"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Uragan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DisableTaskMgr" ascii //weight: 1
        $x_1_2 = "README.txt" ascii //weight: 1
        $x_1_3 = "Global\\UraganMutex" ascii //weight: 1
        $x_1_4 = "lock.png" ascii //weight: 1
        $x_1_5 = "encrypted your infrastructure" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

