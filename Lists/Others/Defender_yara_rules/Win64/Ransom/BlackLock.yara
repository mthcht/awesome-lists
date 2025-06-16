rule Ransom_Win64_BlackLock_GKP_2147943767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackLock.GKP!MTB"
        threat_id = "2147943767"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sensitive data was exfiltrated and your systems were encrypted" ascii //weight: 1
        $x_1_2 = "Irreversible loss of your encrypted data" ascii //weight: 1
        $x_1_3 = "we have stolen your data" ascii //weight: 1
        $x_1_4 = ".onion/chat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

