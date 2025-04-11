rule Ransom_Win64_CrazyHunter_YAC_2147938649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/CrazyHunter.YAC!MTB"
        threat_id = "2147938649"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "CrazyHunter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "Prince-Ransomware" ascii //weight: 1
        $x_1_3 = "I'm CrazyHunter" ascii //weight: 1
        $x_10_4 = "encrypted all your systems" ascii //weight: 10
        $x_1_5 = "stole your file" ascii //weight: 1
        $x_1_6 = "made public" ascii //weight: 1
        $x_1_7 = "delete all the data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

