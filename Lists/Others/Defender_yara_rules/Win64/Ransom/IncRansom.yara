rule Ransom_Win64_IncRansom_YAC_2147941994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/IncRansom.YAC!MTB"
        threat_id = "2147941994"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "IncRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "encrypted with military-grade" ascii //weight: 10
        $x_5_2 = "COMPUTER HAS BEEN SEIZED" ascii //weight: 5
        $x_5_3 = "pay me bro" ascii //weight: 5
        $x_1_4 = {15 f9 00 00 c7 85 ?? ?? ?? ?? 9c 80 00 00 c7 85 ?? ?? ?? ?? 06 a9 00 00 c7 85 ?? ?? ?? ?? 79 60 01 00 c7 85 ?? ?? ?? ?? f7 cd 00 00 c7 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

