rule Ransom_Win64_PrinceRansom_YAA_2147918525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PrinceRansom.YAA!MTB"
        threat_id = "2147918525"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PrinceRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Prince-Ransomware" ascii //weight: 1
        $x_1_2 = "Go buildinf:" ascii //weight: 1
        $x_1_3 = "files have been encrypted" ascii //weight: 1
        $x_1_4 = "paying us a ransom" ascii //weight: 1
        $x_1_5 = "not modify or rename encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_PrinceRansom_MX_2147935759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PrinceRansom.MX!MTB"
        threat_id = "2147935759"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PrinceRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Prince-Ransomware" ascii //weight: 1
        $x_1_2 = "Go build" ascii //weight: 1
        $x_1_3 = "EncryptDirectory" ascii //weight: 1
        $x_1_4 = "setWallpaper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

