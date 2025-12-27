rule Ransom_Win64_TherRansom_YAC_2147946108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/TherRansom.YAC!MTB"
        threat_id = "2147946108"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "TherRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "YOU HAVE BEEN HACKED BY THEFOLLOWERS" ascii //weight: 10
        $x_2_2 = "ALL OF YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 2
        $x_2_3 = "WannaCry - Ransomware" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

